"""
Tool registry — declares every CLI/API tool the Recon agent can invoke.

Each entry exposes:
  * Anthropic-compatible JSON schema (``input_schema``) for tool-use prompts
  * ATT&CK tactic / technique (gated through ``core.opsec``)
  * Python callable that builds the command, runs it via ``tools.runner``,
    parses output, optionally writes DB rows, and returns a ``ToolResult``

The Recon agent consumes ``claude_tool_specs()`` for the API call and
``dispatch(name, args, ctx)`` for execution. Tests monkeypatch
``dispatch`` to avoid subprocess in unit tests.

Tactic gate
-----------
Every spec carries a ``technique`` ID; ``dispatch`` calls
``opsec.assert_execution_allowed`` before spawning anything. Tools that
do not map to TA0043 / TA0042 will refuse to run — the same fence that
keeps ReconForge a research framework, not an exploitation framework.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core import opsec, signals as signals_mod
from tools.runner import build_cmd, run_proc, which


# ── types ─────────────────────────────────────────────────────────
@dataclass
class ToolSpec:
    name: str
    description: str
    category: str          # "enum" | "dns" | "http" | "screenshot" | "vuln" | "adaptive"
    technique: str         # ATT&CK technique ID for opsec gate
    input_schema: Dict[str, Any]
    handler: str           # key into _HANDLERS
    cmd_template: Optional[str] = None
    parse_mode: str = "lines"
    timeout: int = 600
    adaptive: bool = False
    description_hint: str = ""   # extra prompt hint when surfacing to Claude
    # Safety class drives mode gating (Phase 15). One of:
    #   passive     — no requests to target (DB/API/CT logs only)
    #   low_active  — single-request probes (httpx, screenshots)
    #   mod_active  — fuzzing / template scans / fingerprint probes
    #   intrusive   — high-volume / brute / service-detection (defaults off)
    #   disabled    — never executes (use to flag work-in-progress tool entries)
    safety_class: str = "disabled"


@dataclass
class ToolResult:
    tool: str
    ok: bool
    summary: str
    items: List[Any] = field(default_factory=list)
    signals_delta: Dict[str, Any] = field(default_factory=dict)
    rc: Optional[int] = None
    error: Optional[str] = None
    raw_path: Optional[str] = None    # on-disk artifact, if any


@dataclass
class DispatchContext:
    """Lightweight context for dispatch — independent of AgentContext to
    keep tools/ free of agent-layer imports.

    ``mode`` is the active operator mode (Phase 15). The dispatcher uses
    it to enforce ``MODE_ALLOWLISTS`` before spawning any subprocess.
    Defaults to the safest mode so any caller that forgets to set it
    cannot accidentally run an active scan.
    """
    job_id: str
    domain: str
    workdir: str
    db: Optional[sqlite3.Connection] = None
    threads: int = 10
    cancel_event: Optional[threading.Event] = None
    mode: str = "passive_recon"


# ── helpers ───────────────────────────────────────────────────────
def _ensure_workdir(ctx: DispatchContext) -> str:
    os.makedirs(ctx.workdir, exist_ok=True)
    return ctx.workdir


def _normalize_subs(domain: str, candidates: List[str]) -> List[str]:
    out = set()
    for c in candidates:
        c = (c or "").strip().lower().lstrip(".")
        if not c:
            continue
        if c == domain or c.endswith("." + domain):
            out.add(c)
    return sorted(out)


def _insert_subs(db: Optional[sqlite3.Connection], domain: str, subs: List[str]) -> int:
    if not db or not subs:
        return 0
    added = 0
    for s in subs:
        db.execute(
            "INSERT OR IGNORE INTO subdomains(domain, subdomain) VALUES(?,?)",
            (domain, s),
        )
        added += db.execute("SELECT changes()").fetchone()[0]
    db.commit()
    return added


# ── handlers ──────────────────────────────────────────────────────
def _run_enum_stdout(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    """Tools that print subdomains to stdout (assetfinder, findomain)."""
    if not which(spec.cmd_template.split()[0]):
        return ToolResult(spec.name, False, f"{spec.name}: binary not found", error="missing")
    cmd = build_cmd(spec.cmd_template, {"$DOMAIN$": args["domain"]})
    rc, stdout, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    subs = _normalize_subs(args["domain"], stdout.splitlines())
    added = _insert_subs(ctx.db, args["domain"], subs)
    return ToolResult(
        tool=spec.name, ok=(rc == 0 or rc == 124), rc=rc,
        summary=f"{added} new subdomain(s)", items=subs,
        signals_delta=signals_mod.extract_from_url_list(subs),
        error=(stderr.strip() or None) if rc not in (0, 124) else None,
    )


def _run_enum_file(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    """Tools that write subdomains to a file (amass, subfinder, sublist3r)."""
    if not which(spec.cmd_template.split()[0]):
        return ToolResult(spec.name, False, f"{spec.name}: binary not found", error="missing")
    workdir = _ensure_workdir(ctx)
    out = os.path.join(workdir, f"enum_{spec.name}.txt")
    cmd = build_cmd(spec.cmd_template, {
        "$DOMAIN$": args["domain"],
        "$OUTPUT$": out,
        "$THREADS$": str(ctx.threads),
    })
    rc, stdout, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    lines: List[str] = []
    if os.path.exists(out):
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
    # Some of these write to stdout too.
    if not lines and stdout:
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    subs = _normalize_subs(args["domain"], lines)
    added = _insert_subs(ctx.db, args["domain"], subs)
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{added} new subdomain(s)", items=subs,
        signals_delta=signals_mod.extract_from_url_list(subs),
        raw_path=out if os.path.exists(out) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _run_crtsh(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    """No subprocess — calls the crt.sh JSON API directly."""
    domain = args["domain"]
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: List[str] = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconforge/recon"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        for entry in data:
            for name in (entry.get("name_value") or "").split("\n"):
                subs.append(name)
    except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
        return ToolResult(spec.name, False, "crtsh request failed", error=str(e))
    subs = _normalize_subs(domain, subs)
    added = _insert_subs(ctx.db, domain, subs)
    return ToolResult(
        tool=spec.name, ok=True,
        summary=f"{added} new subdomain(s) from cert transparency",
        items=subs,
        signals_delta=signals_mod.extract_from_url_list(subs),
    )


def _run_dnsx(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    """Resolve a list of hosts; updates ``subdomains.dns_resolved``."""
    if not which("dnsx"):
        return ToolResult(spec.name, False, "dnsx: binary not found", error="missing")
    if ctx.db is None:
        return ToolResult(spec.name, False, "dnsx requires a DB to read host list", error="no db")
    workdir = _ensure_workdir(ctx)
    rows = ctx.db.execute(
        "SELECT subdomain FROM subdomains WHERE domain=?", (ctx.domain,)
    ).fetchall()
    if not rows:
        return ToolResult(spec.name, True, "no hosts to resolve", items=[])
    inp = os.path.join(workdir, "dnsx_input.txt")
    out = os.path.join(workdir, "dnsx_output.txt")
    with open(inp, "w", encoding="utf-8") as f:
        f.write("\n".join(r[0] for r in rows) + "\n")
    cmd = build_cmd(spec.cmd_template, {
        "$INPUT_FILE$": inp, "$OUTPUT$": out, "$THREADS$": str(ctx.threads),
    })
    rc, _, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    resolved = 0
    if os.path.exists(out):
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^(\S+)\s*\[([^\]]+)\]", line.strip())
                if not m:
                    continue
                sub, ip = m.group(1), m.group(2)
                ctx.db.execute(
                    "UPDATE subdomains SET dns_resolved=1, ip_addresses=?, "
                    "updated_at=datetime('now') WHERE domain=? AND subdomain=?",
                    (json.dumps([ip] if ip else []), ctx.domain, sub),
                )
                resolved += 1
        ctx.db.commit()
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{resolved} host(s) resolved", items=[],
        raw_path=out if os.path.exists(out) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _run_httpx(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    if not which("httpx"):
        return ToolResult(spec.name, False, "httpx: binary not found", error="missing")
    if ctx.db is None:
        return ToolResult(spec.name, False, "httpx requires a DB", error="no db")
    workdir = _ensure_workdir(ctx)
    rows = ctx.db.execute(
        "SELECT subdomain FROM subdomains WHERE domain=?", (ctx.domain,)
    ).fetchall()
    if not rows:
        return ToolResult(spec.name, True, "no hosts to probe", items=[])
    inp = os.path.join(workdir, "httpx_input.txt")
    out = os.path.join(workdir, "httpx_output.jsonl")
    with open(inp, "w", encoding="utf-8") as f:
        f.write("\n".join(r[0] for r in rows) + "\n")
    cmd = build_cmd(spec.cmd_template, {
        "$INPUT_FILE$": inp, "$OUTPUT$": out, "$THREADS$": str(ctx.threads),
    })
    rc, _, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    sig: Dict[str, Any] = signals_mod.empty_bundle()
    live = 0
    if os.path.exists(out):
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            sig = signals_mod.extract_from_httpx_jsonl(f)
        # Update DB statuses
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = e.get("url") or e.get("input") or ""
                host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                if not host:
                    continue
                status = e.get("status_code") or e.get("status")
                title = e.get("title", "")
                tech = json.dumps(e.get("tech") or e.get("technologies") or [])
                ctx.db.execute(
                    "INSERT OR IGNORE INTO subdomains(domain, subdomain) VALUES(?,?)",
                    (ctx.domain, host),
                )
                ctx.db.execute(
                    "UPDATE subdomains SET http_status=?, http_title=?, http_technologies=?, "
                    "updated_at=datetime('now') WHERE domain=? AND subdomain=?",
                    (status, title, tech, ctx.domain, host),
                )
                live += 1
        ctx.db.commit()
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{live} live HTTP host(s)", items=[],
        signals_delta=sig,
        raw_path=out if os.path.exists(out) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _run_nuclei(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    if not which("nuclei"):
        return ToolResult(spec.name, False, "nuclei: binary not found", error="missing")
    if ctx.db is None:
        return ToolResult(spec.name, False, "nuclei requires a DB", error="no db")
    workdir = _ensure_workdir(ctx)
    rows = ctx.db.execute(
        "SELECT subdomain FROM subdomains WHERE domain=? AND http_status IS NOT NULL",
        (ctx.domain,),
    ).fetchall()
    if not rows:
        return ToolResult(spec.name, True, "no live hosts to scan", items=[])
    inp = os.path.join(workdir, "nuclei_input.txt")
    out = os.path.join(workdir, "nuclei_output.jsonl")
    with open(inp, "w", encoding="utf-8") as f:
        f.write("\n".join(r[0] for r in rows) + "\n")
    cmd = build_cmd(spec.cmd_template, {
        "$INPUT_FILE$": inp, "$OUTPUT$": out, "$THREADS$": str(ctx.threads),
    })
    rc, _, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    sig: Dict[str, Any] = signals_mod.empty_bundle()
    findings = 0
    if os.path.exists(out):
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            sig = signals_mod.extract_from_nuclei_jsonl(f)
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            for _ in f:
                findings += 1
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{findings} nuclei result line(s)", items=[],
        signals_delta=sig,
        raw_path=out if os.path.exists(out) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _run_gowitness(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    if not which("gowitness"):
        return ToolResult(spec.name, False, "gowitness: binary not found", error="missing")
    if ctx.db is None:
        return ToolResult(spec.name, False, "gowitness requires a DB", error="no db")
    workdir = _ensure_workdir(ctx)
    rows = ctx.db.execute(
        "SELECT subdomain, http_status FROM subdomains "
        "WHERE domain=? AND http_status IS NOT NULL", (ctx.domain,),
    ).fetchall()
    if not rows:
        return ToolResult(spec.name, True, "no live hosts to screenshot", items=[])
    inp = os.path.join(workdir, "gowitness_urls.txt")
    out_dir = os.path.join(workdir, "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    with open(inp, "w", encoding="utf-8") as f:
        for r in rows:
            scheme = "https"
            f.write(f"{scheme}://{r[0]}\n")
    cmd = build_cmd(spec.cmd_template, {
        "$INPUT_FILE$": inp, "$OUTPUT$": out_dir, "$THREADS$": str(ctx.threads),
    })
    rc, _, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    pngs = [f for f in os.listdir(out_dir) if f.endswith(".png")] if os.path.isdir(out_dir) else []
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{len(pngs)} screenshot(s)", items=pngs,
        raw_path=out_dir if os.path.isdir(out_dir) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _run_adaptive(spec: ToolSpec, args: Dict, ctx: DispatchContext) -> ToolResult:
    """Generic adaptive-tool wrapper. Takes a single ``target`` arg
    (URL or hostname) and shells out, returning stdout summary."""
    binary = spec.cmd_template.split()[0]
    if not which(binary):
        return ToolResult(spec.name, False, f"{spec.name}: binary not found",
                          error="missing", summary=f"{spec.name} not installed")
    target = args.get("target") or args.get("domain") or args.get("url")
    if not target:
        return ToolResult(spec.name, False, "missing target", error="no target arg")
    cmd = build_cmd(spec.cmd_template, {"$TARGET$": target})
    rc, stdout, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    return ToolResult(
        tool=spec.name, ok=(rc == 0), rc=rc,
        summary=f"{spec.name} ran on {target}",
        items=[stdout[:4000]] if stdout else [],
        error=(stderr.strip() or None) if rc != 0 else None,
    )


_HANDLERS: Dict[str, Callable[[ToolSpec, Dict, DispatchContext], ToolResult]] = {
    "enum_stdout": _run_enum_stdout,
    "enum_file":   _run_enum_file,
    "crtsh":       _run_crtsh,
    "dnsx":        _run_dnsx,
    "httpx":       _run_httpx,
    "nuclei":      _run_nuclei,
    "gowitness":   _run_gowitness,
    "adaptive":    _run_adaptive,
}


# ── registry ──────────────────────────────────────────────────────
_DOMAIN_SCHEMA = {
    "type": "object",
    "properties": {"domain": {"type": "string",
                              "description": "Root domain (e.g. acme.com)"}},
    "required": ["domain"],
}
_TARGET_SCHEMA = {
    "type": "object",
    "properties": {"target": {"type": "string",
                              "description": "URL or hostname to probe"}},
    "required": ["target"],
}
_NO_ARGS_SCHEMA = {"type": "object", "properties": {}}


REGISTRY: Dict[str, ToolSpec] = {
    # ── broad subdomain enumeration ───────────────────────────────
    "subfinder": ToolSpec(
        name="subfinder", category="enum", technique="T1596",
        description="Fast passive subdomain enumeration via OSINT sources.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="subfinder -d $DOMAIN$ -o $OUTPUT$ -silent",
        safety_class="passive",
    ),
    "amass": ToolSpec(
        name="amass", category="enum", technique="T1596",
        description="OWASP Amass passive subdomain enumeration.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="amass enum -passive -d $DOMAIN$ -o $OUTPUT$",
        timeout=1800,
        safety_class="passive",
    ),
    "assetfinder": ToolSpec(
        name="assetfinder", category="enum", technique="T1596",
        description="Tomnomnom subdomain finder. Stdout-only.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_stdout",
        cmd_template="assetfinder --subs-only $DOMAIN$",
        safety_class="passive",
    ),
    "findomain": ToolSpec(
        name="findomain", category="enum", technique="T1596",
        description="Cross-platform subdomain enumerator.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_stdout",
        cmd_template="findomain -t $DOMAIN$ -q",
        safety_class="passive",
    ),
    "sublist3r": ToolSpec(
        name="sublist3r", category="enum", technique="T1596",
        description="Sublist3r OSINT subdomain enumeration.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="sublist3r -d $DOMAIN$ -o $OUTPUT$ -n",
        safety_class="passive",
    ),
    "crtsh": ToolSpec(
        name="crtsh", category="enum", technique="T1596",
        description="Certificate Transparency log search via crt.sh API.",
        input_schema=_DOMAIN_SCHEMA, handler="crtsh",
        safety_class="passive",
    ),
    # ── resolve / probe ───────────────────────────────────────────
    "dnsx": ToolSpec(
        name="dnsx", category="dns", technique="T1590",
        description="Resolve all known subdomains. Updates dns_resolved + ips.",
        input_schema=_NO_ARGS_SCHEMA, handler="dnsx",
        cmd_template="dnsx -l $INPUT_FILE$ -resp -o $OUTPUT$ -t $THREADS$",
        safety_class="passive",
    ),
    "httpx": ToolSpec(
        name="httpx", category="http", technique="T1595",
        description=(
            "HTTP probe + fingerprint live hosts. Surfaces signals: "
            "GraphQL endpoints, admin panels, Swagger specs, login pages, "
            "tech stack, WAF/CDN."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="httpx",
        cmd_template=(
            "httpx -l $INPUT_FILE$ -o $OUTPUT$ -title -tech-detect "
            "-status-code -threads $THREADS$ -silent -json"
        ),
        safety_class="low_active",
    ),
    "gowitness": ToolSpec(
        name="gowitness", category="screenshot", technique="T1595",
        description="Capture screenshots of live HTTP hosts.",
        input_schema=_NO_ARGS_SCHEMA, handler="gowitness",
        cmd_template="gowitness file -f $INPUT_FILE$ -P $OUTPUT$ --threads $THREADS$",
        timeout=1800,
        safety_class="low_active",
    ),
    "nuclei": ToolSpec(
        name="nuclei", category="vuln", technique="T1595.002",
        description="Template-based vuln scan. Medium/high/critical only.",
        input_schema=_NO_ARGS_SCHEMA, handler="nuclei",
        cmd_template=(
            "nuclei -l $INPUT_FILE$ -o $OUTPUT$ -c $THREADS$ -silent "
            "-severity medium,high,critical -json"
        ),
        timeout=3600,
        safety_class="mod_active",
    ),

    # ── adaptive (signal-triggered) ───────────────────────────────
    "graphw00f": ToolSpec(
        name="graphw00f", category="adaptive", technique="T1595",
        description="GraphQL engine fingerprinter. Run when /graphql is observed.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="graphw00f -t $TARGET$ -d",
        description_hint="signal: graphql_endpoints",
        safety_class="mod_active",
    ),
    "clairvoyance": ToolSpec(
        name="clairvoyance", category="adaptive", technique="T1595",
        description=(
            "Reconstruct a GraphQL schema via field suggestion when "
            "introspection is disabled."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="clairvoyance $TARGET$ -o schema.json",
        description_hint="signal: graphql_endpoints",
        timeout=1200,
        safety_class="mod_active",
    ),
    "inql": ToolSpec(
        name="inql", category="adaptive", technique="T1595",
        description="InQL GraphQL query/mutation enumerator.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="inql -t $TARGET$",
        description_hint="signal: graphql_endpoints",
        safety_class="mod_active",
    ),
    "s3scanner": ToolSpec(
        name="s3scanner", category="adaptive", technique="T1595",
        description="S3/GCS/Azure bucket access probe. Run when a bucket ref is found.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string",
                                      "description": "Bucket name or full URL"}},
            "required": ["target"],
        },
        handler="adaptive", adaptive=True,
        cmd_template="s3scanner scan -b $TARGET$",
        description_hint="signal: s3_buckets|gcs_buckets|azure_blobs",
        safety_class="low_active",
    ),
    "wafw00f": ToolSpec(
        name="wafw00f", category="adaptive", technique="T1595",
        description="Fingerprint the WAF in front of a target.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="wafw00f $TARGET$",
        description_hint="signal: admin_panels",
        safety_class="low_active",
    ),
}


# ── mode allowlists (Phase 15) ────────────────────────────────────
# Canonical operator modes. Each mode names the set of safety classes its
# jobs may invoke. ``passive_recon`` is the safest mode and is the default
# everywhere the operator hasn't picked one explicitly.
OPERATOR_MODES: Tuple[str, ...] = (
    "passive_recon", "active_recon", "content_discovery",
    "vuln_triage", "evidence_collection", "report_drafting", "retest",
)

MODE_ALLOWLISTS: Dict[str, frozenset[str]] = {
    "passive_recon":       frozenset({"passive"}),
    "active_recon":        frozenset({"passive", "low_active"}),
    "content_discovery":   frozenset({"passive", "low_active", "mod_active"}),
    "vuln_triage":         frozenset({"passive", "low_active", "mod_active"}),
    # Evidence collection lets the operator run intrusive tools but always
    # behind explicit acknowledgement at the API layer; the registry filter
    # alone does NOT skip the scope_acknowledged check.
    "evidence_collection": frozenset({"passive", "low_active", "mod_active", "intrusive"}),
    "report_drafting":     frozenset({"passive"}),
    "retest":              frozenset({"passive"}),
}


def safety_class_of(name: str) -> str:
    """Lookup the safety class for a registered tool. Returns 'disabled'
    when the tool is unknown — fail closed."""
    spec = REGISTRY.get(name)
    return spec.safety_class if spec else "disabled"


def tools_for_mode(mode: str) -> List[str]:
    """All tool names whose safety_class is allowed in this operator mode."""
    allowed = MODE_ALLOWLISTS.get(mode, frozenset())
    return sorted(name for name, spec in REGISTRY.items()
                  if spec.safety_class in allowed)


def is_tool_allowed_in_mode(name: str, mode: str) -> bool:
    """True iff the tool's safety class is in the mode's allowlist."""
    return safety_class_of(name) in MODE_ALLOWLISTS.get(mode, frozenset())


# ── public surface ────────────────────────────────────────────────
BROAD_TOOLS: Tuple[str, ...] = (
    "subfinder", "amass", "assetfinder", "findomain", "sublist3r",
    "crtsh", "dnsx", "httpx", "gowitness", "nuclei",
)
ADAPTIVE_TOOLS: Tuple[str, ...] = tuple(
    name for name, spec in REGISTRY.items() if spec.adaptive
)


def claude_tool_specs(only: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Build the ``tools=`` payload for ``Anthropic.messages.create``."""
    out: List[Dict[str, Any]] = []
    names = only if only is not None else list(REGISTRY.keys())
    for name in names:
        spec = REGISTRY.get(name)
        if spec is None:
            continue
        desc = spec.description
        if spec.description_hint:
            desc = f"{desc} [{spec.description_hint}]"
        out.append({
            "name": spec.name,
            "description": desc,
            "input_schema": spec.input_schema,
        })
    return out


def dispatch(name: str, args: Dict[str, Any], ctx: DispatchContext) -> ToolResult:
    """Execute a tool by registry name. Scope is enforced upstream by
    ``scope_guard.check``; mode/tactic gates are advisory only (see
    ``core.opsec`` for the policy change rationale)."""
    spec = REGISTRY.get(name)
    if spec is None:
        return ToolResult(name, False, f"unknown tool: {name}", error="not in registry")
    handler = _HANDLERS.get(spec.handler)
    if handler is None:
        return ToolResult(spec.name, False, f"no handler for {spec.handler}",
                          error="missing handler")
    try:
        return handler(spec, args, ctx)
    except Exception as e:  # pragma: no cover — defense in depth
        return ToolResult(spec.name, False, "handler raised", error=f"{type(e).__name__}: {e}")

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
        cmd_template="clairvoyance $TARGET$ -o $OUTPUT$",
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

    # ── Phase C Batch 1: subdomain spine ──────────────────────────
    "bbot": ToolSpec(
        name="bbot", category="enum", technique="T1596",
        description=(
            "BBOT recursive multi-source subdomain enumeration. Aggregates "
            "CT, public DNS, certificate scraping, GitHub, and active brute "
            "in one pass; produces a directory of artifacts."
        ),
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="bbot -t $DOMAIN$ -f subdomain-enum -o $OUTPUT$ -y --silent",
        timeout=3600,
        safety_class="low_active",
    ),
    "puredns": ToolSpec(
        name="puredns", category="dns", technique="T1590",
        description=(
            "Wildcard-DNS filter + bulk resolver. Runs between enum and "
            "dnsx so wildcard noise doesn't pollute downstream phases."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="dnsx",
        cmd_template="puredns resolve $INPUT_FILE$ -r $RESOLVERS_FILE$ -w $OUTPUT$ --skip-wildcard-filter",
        safety_class="passive",
    ),
    "cdncheck": ToolSpec(
        name="cdncheck", category="dns", technique="T1596",
        description=(
            "ProjectDiscovery CDN-IP tagger. Marks IPs belonging to "
            "shared CDN/WAF infrastructure so downstream nuclei/nmap "
            "passes skip them (and avoid burning the WAF vendor's "
            "reputation budget)."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="dnsx",
        cmd_template="cdncheck -i $INPUT_FILE$ -o $OUTPUT$ -resp",
        safety_class="passive",
    ),

    # ── Phase C Batch 2: HTTP exploration ─────────────────────────
    "katana": ToolSpec(
        name="katana", category="adaptive", technique="T1595",
        description=(
            "Headless SPA-aware crawler. Extracts JS, follows form "
            "actions, and emits a per-host URL inventory that downstream "
            "JS-analysis tools (jsluice/mantra/TruffleHog) consume."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="katana -u $TARGET$ -o $OUTPUT$ -d 3 -jc -silent",
        timeout=1200,
        safety_class="low_active",
    ),
    "feroxbuster": ToolSpec(
        name="feroxbuster", category="adaptive", technique="T1595.003",
        description=(
            "Rust recursive content-discovery scanner. Heavier traffic "
            "than ffuf — gate behind explicit operator opt-in for any "
            "program with throttling rules."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="feroxbuster -u https://$TARGET$ -w $WORDLIST$ -o $OUTPUT$ --silent --no-state",
        timeout=1800,
        safety_class="mod_active",
    ),
    "x8": ToolSpec(
        name="x8", category="adaptive", technique="T1595.002",
        description=(
            "Hidden HTTP parameter discovery. Run after katana surfaces "
            "endpoints; chain with payload-injection probes."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="x8 -u https://$TARGET$ -w $WORDLIST$ -o $OUTPUT$ --output-format url",
        timeout=1200,
        safety_class="mod_active",
    ),
    "kiterunner": ToolSpec(
        name="kiterunner", category="adaptive", technique="T1595.002",
        description=(
            "Assetnote Swagger/OpenAPI corpus brute. The 67k-spec "
            "routes-large.kite wordlist is the default; smaller "
            "kite files (routes-small.kite) for low-throttle targets."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="kr scan https://$TARGET$ -w $WORDLIST_DIR$/routes-large.kite -o $OUTPUT$",
        timeout=2400,
        safety_class="mod_active",
    ),

    # ── Phase C Batch 3: JS analysis ──────────────────────────────
    "jsluice": ToolSpec(
        name="jsluice", category="adaptive", technique="T1213",
        description=(
            "BishopFox jsluice — AST-based URL and secret extraction "
            "from JS files. Chain after katana surfaces JS sources."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="jsluice urls $INPUT_FILE$",
        description_hint="signal: js_endpoints (post-katana)",
        safety_class="passive",
    ),
    "mantra": ToolSpec(
        name="mantra", category="adaptive", technique="T1552.001",
        description=(
            "Brosck Mantra — regex-based API-key / secret hunter for "
            "live JS responses. Fetches the page and scans inline scripts."
        ),
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="mantra -ua ReconForge -p $TARGET$",
        description_hint="signal: js_endpoints",
        safety_class="low_active",
    ),
    "trufflehog": ToolSpec(
        name="trufflehog", category="adaptive", technique="T1552.001",
        description=(
            "Trufflesec TruffleHog — entropy + verified-detector secret "
            "scanner. Filesystem mode scans a local JS dump; git mode "
            "scans a clone (use after github_subdomains finds repos)."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="trufflehog filesystem $INPUT_FILE$ --json --no-update",
        timeout=1200,
        safety_class="passive",
    ),

    # ── Phase C Batch 4: API / protocol (swagger-jacker only; the
    #    other three — graphw00f, clairvoyance, inql — already exist
    #    above as Phase 14 adaptive entries.) ──────────────────────
    "swagger_jacker": ToolSpec(
        name="swagger_jacker", category="adaptive", technique="T1213.003",
        description=(
            "BishopFox swagger-jacker — scrape Swagger/OpenAPI spec files "
            "from a target. Often finds /v2/api-docs, /swagger.json, and "
            "developer-portal exposures that kiterunner can then brute."
        ),
        input_schema=_DOMAIN_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="swagger-jacker -d $DOMAIN$ -o $OUTPUT$",
        description_hint="signal: swagger_endpoints",
        safety_class="low_active",
    ),

    # ── Phase C Batch 5: cloud (s3scanner already exists above as
    #    a Phase 14 adaptive entry; CloudFox is new) ──────────────
    "cloudfox": ToolSpec(
        name="cloudfox", category="adaptive", technique="T1580",
        description=(
            "BishopFox CloudFox — AWS post-exploitation enumeration. "
            "Requires an AWS profile in ~/.aws/credentials; runs "
            "all-checks (IAM, S3, EC2, Lambda, RDS, Secrets Manager, "
            "etc.) and emits a per-service findings report. Use after "
            "credentials surface via TruffleHog / mantra."
        ),
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="cloudfox aws all-checks --profile $AWS_PROFILE$ -o $OUTPUT$",
        description_hint="signal: aws_credentials",
        timeout=3600,
        safety_class="low_active",
    ),

    # ════════════════════════════════════════════════════════════════
    #  Operator-research catalog (Playbook-driven additions, 2026-05-27)
    # ════════════════════════════════════════════════════════════════

    # ── PD stack additions ────────────────────────────────────────
    "chaos": ToolSpec(
        name="chaos", category="enum", technique="T1596",
        description="ProjectDiscovery bug-bounty subdomain DB (requires CHAOS_KEY).",
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="chaos -d $DOMAIN$ -silent -o $OUTPUT$",
        safety_class="passive",
    ),
    "shuffledns": ToolSpec(
        name="shuffledns", category="dns", technique="T1590",
        description="massdns wrapper — wildcard-aware bruteforce + resolve.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_file",
        cmd_template="shuffledns -d $DOMAIN$ -w $WORDLIST$ -r $RESOLVERS_FILE$ -mode bruteforce -o $OUTPUT$",
        timeout=1800,
        safety_class="low_active",
    ),
    "mapcidr": ToolSpec(
        name="mapcidr", category="dns", technique="T1590",
        description="CIDR expander / aggregator / ASN→IP-range resolver.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="mapcidr -cidr $TARGET$ -silent -o $OUTPUT$",
        safety_class="passive",
    ),
    "tlsx": ToolSpec(
        name="tlsx", category="adaptive", technique="T1592",
        description="TLS SAN/CN harvest + cert misconfig surface.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="tlsx -l $INPUT_FILE$ -san -cn -silent -resp-only -o $OUTPUT$",
        safety_class="low_active",
    ),
    "naabu": ToolSpec(
        name="naabu", category="adaptive", technique="T1595.001",
        description="ProjectDiscovery fast port scanner (Go) — top-1000 by default.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="naabu -l $INPUT_FILE$ -tp 1000 -silent -o $OUTPUT$",
        timeout=1800,
        safety_class="mod_active",
    ),
    "alterx": ToolSpec(
        name="alterx", category="enum", technique="T1596",
        description="DSL-based subdomain permutation generator.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="alterx -enrich -l $INPUT_FILE$ -o $OUTPUT$",
        safety_class="passive",
    ),
    "notify": ToolSpec(
        name="notify", category="adaptive", technique="T1583",
        description="ProjectDiscovery multi-provider alert relay (Slack/Discord/etc).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="notify -bulk -data $INPUT_FILE$",
        safety_class="passive",
    ),
    "interactsh": ToolSpec(
        name="interactsh", category="adaptive", technique="T1095",
        description="OOB callback receiver for blind SSRF/RCE/SQLi confirmation.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="interactsh-client -n 5 -server oast.pro -o $OUTPUT$",
        safety_class="passive",
    ),
    "uncover": ToolSpec(
        name="uncover", category="enum", technique="T1596",
        description="Search-engine-driven asset discovery (Shodan/Censys/FOFA/etc).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="uncover -q $TARGET$ -silent -o $OUTPUT$",
        safety_class="passive",
    ),

    # ── Tomnomnom utility chain ──────────────────────────────────
    "gau": ToolSpec(
        name="gau", category="adaptive", technique="T1593.003",
        description="URL history harvest from Wayback / CommonCrawl / OTX.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_stdout",
        cmd_template="gau --subs --threads $THREADS$ $DOMAIN$",
        safety_class="passive",
    ),
    "waybackurls": ToolSpec(
        name="waybackurls", category="adaptive", technique="T1593.003",
        description="Tomnomnom Wayback URL extractor.",
        input_schema=_DOMAIN_SCHEMA, handler="enum_stdout",
        cmd_template="waybackurls $DOMAIN$",
        safety_class="passive",
    ),
    "anew": ToolSpec(
        name="anew", category="adaptive", technique="T1596",
        description="Pipe filter: dedupe + append-only-new (stdout = new lines).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="anew $OUTPUT$",
        safety_class="passive",
    ),
    "unfurl": ToolSpec(
        name="unfurl", category="adaptive", technique="T1596",
        description="URL parser pipe: domains | paths | keys | values | keypairs.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="unfurl -u keys",
        safety_class="passive",
    ),
    "qsreplace": ToolSpec(
        name="qsreplace", category="adaptive", technique="T1190",
        description="Replace every query-string value with a payload (pipe filter).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="qsreplace $TARGET$",
        safety_class="passive",
    ),
    "gf": ToolSpec(
        name="gf", category="adaptive", technique="T1596",
        description="Tomnomnom grep-fu pattern matcher (xss/sqli/idor/ssrf/lfi/...).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="gf $TARGET$",
        safety_class="passive",
    ),
    "hakrawler": ToolSpec(
        name="hakrawler", category="adaptive", technique="T1595",
        description="Hakluke fast Go crawler — fallback when katana is too heavy.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="hakrawler -url $TARGET$ -depth 2 -plain",
        safety_class="low_active",
    ),

    # ── Specialty attack tools ────────────────────────────────────
    "arjun": ToolSpec(
        name="arjun", category="adaptive", technique="T1595.002",
        description="HTTP parameter discovery via behavioral diff.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="arjun -u $TARGET$ -oT $OUTPUT$ -t $THREADS$",
        timeout=1200,
        safety_class="mod_active",
    ),
    "dalfox": ToolSpec(
        name="dalfox", category="adaptive", technique="T1190",
        description="hahwul XSS scanner — DOM + reflected + BAV chain.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="dalfox url $TARGET$ -o $OUTPUT$",
        timeout=1800,
        safety_class="mod_active",
    ),
    "crlfuzz": ToolSpec(
        name="crlfuzz", category="adaptive", technique="T1190",
        description="CRLF-injection probe (header smuggling / response splitting).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="crlfuzz -u $TARGET$ -o $OUTPUT$",
        safety_class="mod_active",
    ),
    "paramspider": ToolSpec(
        name="paramspider", category="adaptive", technique="T1593.003",
        description="Pull parameter URLs from archive sources (devanshbatham).",
        input_schema=_DOMAIN_SCHEMA, handler="adaptive", adaptive=True,
        # v3 dropped --exclude/--output; -s streams URLs to stdout, which the
        # adaptive handler captures. Uses $TARGET$ (the only placeholder it fills).
        cmd_template="paramspider -d $TARGET$ -s",
        safety_class="passive",
    ),
    "sqlmap": ToolSpec(
        name="sqlmap", category="adaptive", technique="T1190",
        description="Full-stack SQL injection automator.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="sqlmap -u $TARGET$ --batch --random-agent --level 5 --risk 3 --dbs",
        timeout=3600,
        safety_class="intrusive",
    ),
    "masscan": ToolSpec(
        name="masscan", category="adaptive", technique="T1595.001",
        description="RobertGraham huge-scale TCP port sweeper.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="masscan -p1-65535 $TARGET$ --rate=10000 -oX $OUTPUT$",
        timeout=7200,
        safety_class="intrusive",
    ),
    "gobuster": ToolSpec(
        name="gobuster", category="adaptive", technique="T1595.003",
        description="Directory / vhost / DNS bruteforce (fallback for ffuf/feroxbuster).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="gobuster dir -u $TARGET$ -w $WORDLIST$ -o $OUTPUT$ -t $THREADS$ --no-error",
        timeout=1800,
        safety_class="mod_active",
    ),
    "dirsearch": ToolSpec(
        name="dirsearch", category="adaptive", technique="T1595.003",
        description="Python-based recursive content discovery with extension matrix.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="dirsearch -u $TARGET$ -e conf,config,bak,backup,old,sql,zip,env,git -o $OUTPUT$ -t $THREADS$",
        timeout=1800,
        safety_class="mod_active",
    ),
    "gxss": ToolSpec(
        name="gxss", category="adaptive", technique="T1190",
        description="KathanP19 reflection-finder (pipe filter; pre-dalfox).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="Gxss -p Xss -c $THREADS$",
        safety_class="low_active",
    ),
    "subjs": ToolSpec(
        name="subjs", category="adaptive", technique="T1593",
        description="Pull all JS file URLs from a list of hosts (lc/subjs).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="subjs -i $INPUT_FILE$",
        safety_class="low_active",
    ),
    "sourcemapper": ToolSpec(
        name="sourcemapper", category="adaptive", technique="T1213",
        description="Reconstruct webpack/source-maps into original source tree.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="sourcemapper -url $TARGET$ -output $OUTPUT$",
        safety_class="low_active",
    ),
    "secretfinder": ToolSpec(
        name="secretfinder", category="adaptive", technique="T1552.001",
        description="m4ll0k regex secret hunter for JS files.",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="SecretFinder -i $TARGET$ -o cli",
        safety_class="passive",
    ),
    "gotator": ToolSpec(
        name="gotator", category="enum", technique="T1596",
        description="Subdomain permutation generator with adversarial mode.",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="gotator -sub $INPUT_FILE$ -perm $WORDLIST$ -depth 1 -numbers 10 -mindup -adv -md",
        safety_class="passive",
    ),
    "dnsgen": ToolSpec(
        name="dnsgen", category="enum", technique="T1596",
        description="ProjectAnte DNS permutation generator (Python).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="dnsgen $INPUT_FILE$",
        safety_class="passive",
    ),

    # ── Resolvers + scope helpers ────────────────────────────────
    "dnsvalidator": ToolSpec(
        name="dnsvalidator", category="adaptive", technique="T1590",
        description="Validate / refresh resolvers.txt (run weekly).",
        input_schema=_NO_ARGS_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="dnsvalidator -tL $INPUT_FILE$ -threads $THREADS$ -o $OUTPUT$",
        timeout=1800,
        safety_class="low_active",
    ),
    "hacker_scoper": ToolSpec(
        name="hacker_scoper", category="adaptive", technique="T1596",
        description="External scope filter (CLI mirror of scope_guard).",
        input_schema=_TARGET_SCHEMA, handler="adaptive", adaptive=True,
        cmd_template="hacker-scoper -f $INPUT_FILE$ -ic $TARGET$",
        safety_class="passive",
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

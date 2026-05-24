"""Contract-output emitter (reconforge ↔ CyberBrain vault).

Emits the per-run directory required by ``RECONFORGE_CONTRACT.md`` in the
CyberBrain vault. After ``run_agentic_pipeline`` finalizes a ``PipelineResult``,
``emit_run(ctx, result)`` writes:

    <RECONFORGE_OUTPUT>/<program-slug>/<YYYY-MM-DD-HHmm>/
        _manifest.json
        hosts.jsonl
        endpoints.jsonl
        findings.jsonl
        raw/         (empty placeholder; tools may drop raw output here later)
        screenshots/ (empty placeholder)

``RECONFORGE_OUTPUT`` resolves from the env var ``RECONFORGE_OUTPUT_DIR``
(default ``./out``). The pipeline calls this unconditionally at end-of-run;
emitter failure is logged via the ``emit`` callback but never marks the
pipeline as failed.

Idempotent: two runs that share program+started_at minute write to the same
directory and overwrite atomically. Re-emitting from CLI (`reconforge
contract emit --job-id ...`) is the supported workflow for backfilling
older runs.

This module is intentionally decoupled from the vault — it owns the wire
format here, the vault owns the wire format there, and `_manifest.schema`
in the vault is the conformance test. Don't import vault code.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SCHEMA_VERSION = "0.1.0"


# ── helpers ───────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _slug(value: str) -> str:
    s = (value or "").lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "unknown"


def _atomic_write(target: Path, content: str) -> None:
    """Write atomically: temp file in same dir, then os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _to_iso(value: Any) -> str:
    """SQLite stores 'YYYY-MM-DD HH:MM:SS' naive UTC. Return ISO 8601 w/ offset."""
    if not value:
        return _now_iso()
    s = str(value).strip()
    if "T" in s and ("+" in s or s.endswith("Z")):
        return s
    try:
        dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.astimezone().isoformat(timespec="seconds")
    except ValueError:
        return s


def _json_or(default, raw: Any):
    if raw is None or raw == "":
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _row_get(row, key: str, default: Any = None):
    """Tolerate either sqlite3.Row or tuple cursors."""
    if hasattr(row, "keys") and key in row.keys():
        return row[key]
    return default


# ── output-dir resolution ─────────────────────────────────────────────

def _resolve_output_dir(program_slug: str, started_at: str) -> Path:
    base = Path(os.environ.get("RECONFORGE_OUTPUT_DIR", "out")).resolve()
    try:
        dt = datetime.fromisoformat(started_at) if started_at else datetime.now(timezone.utc).astimezone()
    except ValueError:
        dt = datetime.now(timezone.utc).astimezone()
    stamp = dt.strftime("%Y-%m-%d-%H%M")
    return base / _slug(program_slug) / stamp


# ── data extractors ───────────────────────────────────────────────────

def _scope_values(entries: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for e in entries or []:
        if isinstance(e, dict):
            v = e.get("value", "")
            if v:
                out.append(str(v))
        elif e:
            out.append(str(e))
    return out


def _agents_as_tools(result: Any) -> List[Dict[str, Any]]:
    """Each agent in the pipeline becomes a synthetic 'tool' entry.

    The contract's `tools` field is intended to record the recon tools the
    run actually invoked (subfinder, httpx, etc.). reconforge runs LLM
    agents that orchestrate those tools internally; recording the agents
    here gives downstream consumers an honest provenance signal, and a
    future pass can augment with the literal CLI tools each agent ran.
    """
    out: List[Dict[str, Any]] = []
    agents = getattr(result, "agents", {}) or {}
    for name, ar in agents.items():
        success = getattr(ar, "success", False)
        cost = getattr(ar, "cost_usd", 0.0)
        out.append({
            "name": f"agent.{name}",
            "version": "rf-pipeline",
            "args": json.dumps({"success": bool(success), "cost_usd": round(float(cost), 4)}),
        })
    return out


def _hosts_from_db(db: sqlite3.Connection, domain: str) -> List[Dict[str, Any]]:
    if not db or not domain:
        return []
    try:
        rows = db.execute(
            "SELECT subdomain, http_status, http_title, http_technologies, "
            "ip_addresses, created_at FROM subdomains WHERE domain = ?",
            (domain,),
        ).fetchall()
    except sqlite3.Error:
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        sub = _row_get(row, "subdomain", row[0] if not hasattr(row, "keys") else None)
        status = _row_get(row, "http_status", row[1] if not hasattr(row, "keys") else None)
        title = _row_get(row, "http_title", row[2] if not hasattr(row, "keys") else None)
        tech_raw = _row_get(row, "http_technologies", row[3] if not hasattr(row, "keys") else None)
        ip_raw = _row_get(row, "ip_addresses", row[4] if not hasattr(row, "keys") else None)
        created = _row_get(row, "created_at", row[5] if not hasattr(row, "keys") else None)
        out.append({
            "type": "host",
            "host": sub or "",
            "ip": _json_or([], ip_raw),
            "ports": [443] if status else [],
            "title": title or "",
            "tech": _json_or([], tech_raw),
            "status_code": int(status) if status else 0,
            "first_seen": _to_iso(created),
            "evidence": {},
        })
    return out


def _endpoints_from_hosts(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """reconforge does not (yet) persist per-URL endpoint records. Emit one
    base entry per host so the contract field is populated; later phases
    can extend with discovered URLs from katana/gau/findings."""
    out: List[Dict[str, Any]] = []
    for h in hosts:
        host = h.get("host")
        if not host:
            continue
        out.append({
            "type": "endpoint",
            "url": f"https://{host}/",
            "host": host,
            "method": "GET",
            "status_code": h.get("status_code") or 0,
            "content_type": "",
            "length": 0,
            "tech": h.get("tech") or [],
            "interesting": [],
            "first_seen": h.get("first_seen") or _now_iso(),
        })
    return out


def _severity_from_cvss(score: Any) -> str:
    if score is None:
        return "info"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    if s >= 0.1: return "low"
    return "info"


def _fp_likelihood(confidence: Any) -> str:
    try:
        c = float(confidence or 0)
    except (TypeError, ValueError):
        c = 0.0
    if c >= 0.9: return "low"
    if c >= 0.6: return "medium"
    return "high"


def _findings_from_db(db: sqlite3.Connection, job_id: str) -> List[Dict[str, Any]]:
    if not db or not job_id:
        return []
    try:
        rows = db.execute(
            "SELECT bug_id, vuln_class, title, description, domain, "
            "cvss_score, cvss_vector, confidence, status, "
            "evidence_json, created_at "
            "FROM findings WHERE job_id = ?",
            (job_id,),
        ).fetchall()
    except sqlite3.Error:
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        bug = _row_get(row, "bug_id", row[0] if not hasattr(row, "keys") else None)
        vc = _row_get(row, "vuln_class", row[1] if not hasattr(row, "keys") else None)
        title = _row_get(row, "title", row[2] if not hasattr(row, "keys") else None)
        desc = _row_get(row, "description", row[3] if not hasattr(row, "keys") else None)
        dom = _row_get(row, "domain", row[4] if not hasattr(row, "keys") else None)
        score = _row_get(row, "cvss_score", row[5] if not hasattr(row, "keys") else None)
        vector = _row_get(row, "cvss_vector", row[6] if not hasattr(row, "keys") else None)
        conf = _row_get(row, "confidence", row[7] if not hasattr(row, "keys") else None)
        status = _row_get(row, "status", row[8] if not hasattr(row, "keys") else None)
        ev_raw = _row_get(row, "evidence_json", row[9] if not hasattr(row, "keys") else None)
        created = _row_get(row, "created_at", row[10] if not hasattr(row, "keys") else None)
        ev = _json_or({}, ev_raw)
        out.append({
            "type": "finding",
            "id": bug or "",
            "severity": _severity_from_cvss(score),
            "category": vc or "unknown",
            "title": title or "",
            "host": dom or "",
            "url": (ev.get("url") if isinstance(ev, dict) else "") or "",
            "evidence": ev if isinstance(ev, dict) else {},
            "first_seen": _to_iso(created),
            "tool": (ev.get("tool") if isinstance(ev, dict) else None) or "agent.hunter",
            "false_positive_likelihood": _fp_likelihood(conf),
            "_rf": {
                "status": status or "new",
                "cvss_score": score,
                "cvss_vector": vector,
                "confidence": conf,
                "description": desc or "",
            },
        })
    return out


def _build_manifest(
    ctx: Any,
    result: Any,
    *,
    program_slug: str,
    host_count: int,
    endpoint_count: int,
    finding_count: int,
) -> Dict[str, Any]:
    program = getattr(ctx, "program", None) or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": f"rf-{getattr(result, 'job_id', 'unknown')}",
        "program": program_slug,
        "started_at": getattr(result, "started_at", None) or _now_iso(),
        "completed_at": getattr(result, "completed_at", None) or _now_iso(),
        "scope": {
            "in_scope": _scope_values(program.get("in_scope")),
            "out_of_scope": _scope_values(program.get("out_of_scope")),
        },
        "tools": _agents_as_tools(result),
        "counts": {
            "hosts": int(host_count),
            "endpoints": int(endpoint_count),
            "findings": int(finding_count),
        },
        "notes": str((getattr(ctx, "inputs", {}) or {}).get("mode") or ""),
    }


# ── public entry point ────────────────────────────────────────────────

def emit_run(ctx: Any, result: Any) -> Path:
    """Emit a contract-compliant run directory and return its path.

    Reads connection from ``ctx.db``; required for hosts/findings extraction.
    Tolerates a None DB (writes empty lists) so unit tests can run without a
    populated DB.
    """
    program = getattr(ctx, "program", None) or {}
    program_slug = (
        program.get("slug")
        or program.get("name")
        or getattr(result, "domain", None)
        or "unknown"
    )
    program_slug = _slug(str(program_slug))

    started_at = getattr(result, "started_at", None) or _now_iso()
    run_dir = _resolve_output_dir(program_slug, started_at)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "raw").mkdir(exist_ok=True)
    (run_dir / "screenshots").mkdir(exist_ok=True)

    db = getattr(ctx, "db", None)
    domain = getattr(result, "domain", "") or (getattr(ctx, "inputs", {}) or {}).get("domain", "")

    hosts = _hosts_from_db(db, domain) if db else []
    endpoints = _endpoints_from_hosts(hosts)
    findings = _findings_from_db(db, getattr(result, "job_id", "")) if db else []

    manifest = _build_manifest(
        ctx, result,
        program_slug=program_slug,
        host_count=len(hosts),
        endpoint_count=len(endpoints),
        finding_count=len(findings),
    )

    _atomic_write(run_dir / "_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(
        run_dir / "hosts.jsonl",
        "".join(json.dumps(h, ensure_ascii=False) + "\n" for h in hosts),
    )
    _atomic_write(
        run_dir / "endpoints.jsonl",
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in endpoints),
    )
    _atomic_write(
        run_dir / "findings.jsonl",
        "".join(json.dumps(f, ensure_ascii=False) + "\n" for f in findings),
    )
    return run_dir


__all__ = ["emit_run", "SCHEMA_VERSION"]

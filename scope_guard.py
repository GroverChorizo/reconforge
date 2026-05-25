#!/usr/bin/env python3
"""
scope_guard.py — pure-logic scope validation. Ships first per CLAUDE.md doctrine.

Zero LLM. Zero network. Returns {allowed, reason, tier, platform, headers, matched}
for every prospective target before any other tool or agent runs.

Invocation today (pre-Phase-4 refactor):
    python scope_guard.py check <target> --program scopes/example.json

Post-refactor: `python -m reconforge.scope_guard ...` will also work.

Scope JSON format (v1, matches CLAUDE.md doctrine):

    {
      "name": "example",
      "platform": "intigriti",                       # h1|intigriti|bugcrowd|yeswehack|synack
      "platform_handle": "<YOUR_HANDLE>",      # populated by setup wizard
      "policy_url": "https://...",
      "in_scope": [
        {"type": "domain",         "value": "example.com",                "tier": 1},
        {"type": "wildcard",       "value": "*.example.com",              "tier": 2},
        {"type": "cidr",           "value": "203.0.113.0/24",             "tier": 3},
        {"type": "mobile_ios",     "value": "com.example.app",            "tier": 2},
        {"type": "mobile_android", "value": "com.example.app",            "tier": 2},
        {"type": "source_code",    "value": "https://github.com/example", "tier": 4}
      ],
      "out_of_scope": [
        {"type": "domain",   "value": "careers.example.com"},
        {"type": "wildcard", "value": "*.dev.example.com"}
      ],
      "bounty_ranges": {"critical": [2000,5000], "high": [1000,3000]}
    }
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

# ── platform header injection per CLAUDE.md ────────────────────────
# Intigriti requires X-Intigriti-Username on every request.
# Other platforms use identifiable User-Agent / custom headers so triage
# can attribute traffic back to the researcher (sacrosanct OPSEC ID).
def platform_headers(platform: str, handle: str) -> Dict[str, str]:
    p = (platform or "").lower()
    if not handle:
        return {}
    if p == "intigriti":
        return {"X-Intigriti-Username": handle}
    if p in ("hackerone", "h1"):
        return {"User-Agent": f"{handle}-bb-research (hackerone.com/{handle})"}
    if p == "bugcrowd":
        return {"X-Bugcrowd-Username": handle}
    if p in ("yeswehack", "ywh"):
        return {"X-YesWeHack-Username": handle}
    if p == "synack":
        return {"X-Synack-Researcher": handle}
    return {}


# ── entry-type constants ───────────────────────────────────────────
_DOMAIN_TYPES   = {"domain", "host", "url"}
_WILDCARD_TYPES = {"wildcard"}
_CIDR_TYPES     = {"cidr", "ip_range", "ip"}
_BUNDLE_TYPES   = {"mobile", "mobile_ios", "mobile_android", "bundle"}
_REPO_TYPES     = {"source_code", "repo", "github"}


# ── helpers ────────────────────────────────────────────────────────
def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _looks_like_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _normalize_host(target: str) -> str:
    """Strip scheme, port, trailing dot, lowercase. Leaves IPs intact."""
    t = target.strip().lower()
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.hostname or t
    # strip port for hostnames and IPv4 (IPv6 uses brackets, urlparse handled it)
    if t.count(":") == 1 and not t.startswith("["):
        head = t.split(":")[0]
        if head and (head[-1].isalpha() or _looks_like_ip(head)):
            t = head
    return t.rstrip(".")


def _entry_value(entry: Any) -> str:
    return entry["value"] if isinstance(entry, dict) else str(entry)


def _entry_type(entry: Any) -> str:
    if isinstance(entry, dict):
        return (entry.get("type") or "domain").lower()
    s = str(entry).strip().lower()
    if s.startswith("*."):
        return "wildcard"
    if _looks_like_cidr(s):
        return "cidr"
    if _looks_like_ip(s):
        return "cidr"  # bare IP treated as /32 or /128
    return "domain"


def _entry_tier(entry: Any, default: int = 2) -> int:
    if isinstance(entry, dict):
        try:
            return int(entry.get("tier", default))
        except (TypeError, ValueError):
            return default
    return default


# ── matchers ───────────────────────────────────────────────────────
def _match_domain(host: str, value: str) -> bool:
    return host == value.lower().rstrip(".")


def _match_wildcard(host: str, pattern: str) -> bool:
    """*.example.com matches a.example.com but NOT example.com itself.

    Per CLAUDE.md: wildcard scope does NOT include the apex unless it's
    also listed explicitly.
    """
    pat = pattern.lower().rstrip(".")
    if not pat.startswith("*."):
        return False
    base = pat[2:]
    if not base:
        return False
    if host == base:
        return False
    return host.endswith("." + base)


def _match_cidr(host: str, cidr: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


def _matches(host: str, raw: str, entry: Any) -> bool:
    et = _entry_type(entry)
    ev = _entry_value(entry).strip().lower()

    if et in _DOMAIN_TYPES:
        return _match_domain(host, ev)
    if et in _WILDCARD_TYPES:
        return _match_wildcard(host, ev)
    if et in _CIDR_TYPES:
        # bare IP becomes /32 or /128 implicitly
        if _looks_like_ip(ev) and "/" not in ev:
            return host == ev
        return _match_cidr(host, ev)
    if et in _BUNDLE_TYPES:
        # bundle IDs match the raw string verbatim (case-insensitive)
        return raw.strip().lower() == ev
    if et in _REPO_TYPES:
        return raw.strip().lower().startswith(ev)
    return False


# ── core check ────────────────────────────────────────────────────
def check(target: str, program: Dict[str, Any]) -> Dict[str, Any]:
    """Validate target against program scope.

    Returns:
        {
            "allowed": bool,
            "reason":  str,
            "tier":    int (-1 when rejected),
            "platform": str,
            "headers": dict[str, str],   # to attach to every outbound request
            "matched": entry | None
        }

    Decision order (CLAUDE.md doctrine):
      1. Out-of-scope entries ALWAYS win, even if also matched by an in-scope rule.
      2. Then look for an in-scope match.
      3. Otherwise reject.
    """
    platform = (program.get("platform") or "").lower()
    handle   = program.get("platform_handle", "")
    headers  = platform_headers(platform, handle)

    raw = (target or "").strip()
    if not raw:
        return {
            "allowed": False, "reason": "empty target",
            "tier": -1, "platform": platform, "headers": headers, "matched": None,
        }

    host = _normalize_host(raw)

    # 1. exclusion wins
    for entry in program.get("out_of_scope", []) or []:
        if _matches(host, raw, entry):
            return {
                "allowed": False,
                "reason": f"out_of_scope: {_entry_type(entry)}={_entry_value(entry)}",
                "tier": -1, "platform": platform, "headers": headers,
                "matched": entry,
            }

    # 2. inclusion
    for entry in program.get("in_scope", []) or []:
        if _matches(host, raw, entry):
            return {
                "allowed": True,
                "reason": f"in_scope: {_entry_type(entry)}={_entry_value(entry)}",
                "tier": _entry_tier(entry),
                "platform": platform, "headers": headers,
                "matched": entry,
            }

    return {
        "allowed": False,
        "reason": "no in_scope rule matched",
        "tier": -1, "platform": platform, "headers": headers, "matched": None,
    }


# ── program loader ────────────────────────────────────────────────
def load_program(path: Union[str, Path]) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ── CLI ───────────────────────────────────────────────────────────
def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="scope_guard",
        description="Validate a target against a program scope.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="Check a single target.")
    pc.add_argument("target")
    pc.add_argument("--program", required=True, help="Path to scope JSON.")

    args = p.parse_args(argv)
    if args.cmd == "check":
        prog = load_program(args.program)
        result = check(args.target, prog)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result["allowed"] else 1
    return 2


if __name__ == "__main__":
    sys.exit(_cli())

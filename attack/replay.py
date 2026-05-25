"""Two-account differential request replay for IDOR detection.

Sends the same request twice with two different auth contexts. If both
return 200 with same-shaped responses, the resource is reachable from
the wrong account — classic IDOR signal.

Caller responsibilities:
  - Both sessions must belong to ACCOUNTS YOU OWN. Replaying with another
    researcher's or a customer's session is unauthorized access.
  - ``target`` is the URL under test; scope_guard has already validated it.
  - ``opts['auth_a']`` and ``opts['auth_b']`` are session cookies / bearer
    tokens for the two accounts.

opts shape::
    {
      "auth_a":     {"Cookie": "session=..."}  | {"Authorization": "Bearer ..."},
      "auth_b":     same shape,
      "method":     "GET" | "POST" | ... (default "GET"),
      "body":       optional dict for non-GET,
      "timeout_s":  default 15,
    }
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict

from .base import AttackResult, _result_error


def _do_request(url: str, method: str, headers: Dict[str, str],
                body: Any, timeout: int) -> Dict[str, Any]:
    data = None
    if body is not None and method != "GET":
        data = json.dumps(body).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {
                "status": resp.status,
                "len":    len(raw),
                "ct":     resp.headers.get("Content-Type", ""),
                "body_head": raw[:300].decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "len":    0,
            "ct":     e.headers.get("Content-Type", "") if e.headers else "",
            "body_head": "",
        }
    except Exception as e:
        return {"status": -1, "len": 0, "ct": "", "body_head": "", "error": str(e)}


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    auth_a = opts.get("auth_a") or {}
    auth_b = opts.get("auth_b") or {}
    if not auth_a or not auth_b:
        return _result_error("idor", "auth_a and auth_b headers required")
    method  = opts.get("method", "GET")
    body    = opts.get("body")
    timeout = int(opts.get("timeout_s", 15))

    resp_a = _do_request(target, method, auth_a, body, timeout)
    resp_b = _do_request(target, method, auth_b, body, timeout)

    # Differential. Same 2xx status + same byte length + same content-type
    # is the highest-confidence signal that B has the same access as A.
    same_status = resp_a["status"] == resp_b["status"]
    same_len    = resp_a["len"] == resp_b["len"]
    both_200    = 200 <= resp_a["status"] < 300 and 200 <= resp_b["status"] < 300
    if both_200 and same_status and same_len:
        confidence = 0.85
        success    = True
        summary    = (f"IDOR: account B got identical {resp_a['status']} "
                      f"response to account A ({resp_a['len']} bytes)")
    elif both_200 and same_status:
        # Same status, different length — partial leak (e.g. paginated lists).
        confidence = 0.55
        success    = True
        summary    = (f"Possible IDOR: account B got {resp_b['status']} "
                      f"(differs from A by {abs(resp_a['len']-resp_b['len'])} bytes)")
    else:
        confidence = 0.0
        success    = False
        summary    = (f"No IDOR: A={resp_a['status']}/{resp_a['len']}B, "
                      f"B={resp_b['status']}/{resp_b['len']}B")

    return AttackResult(
        technique="idor", success=success, confidence=confidence,
        summary=summary,
        evidence=[
            {"role": "account_a", "url": target, "method": method, **resp_a},
            {"role": "account_b", "url": target, "method": method, **resp_b},
        ],
    )

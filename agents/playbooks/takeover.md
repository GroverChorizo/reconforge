# Playbook — Subdomain Takeover

> This playbook is **deterministic**. It is not invoked by an LLM call. The file exists for documentation parity with other playbooks and as a reference for the human operator and the Hunter README.

The implementation lives in `agents/hunter.py::run_takeover`. It walks every row of the `subdomains` table for the active domain and matches HTTP titles against a fingerprint table (`TAKEOVER_FINGERPRINTS`) for known takeover-vulnerable hosting services:

- GitHub Pages
- AWS S3 (bucket-hosted websites)
- Heroku
- Azure Web Apps / Cloud Apps
- Fastly
- Shopify
- Unbounce

## Confidence

- 0.85–0.95 if BOTH the CNAME pattern matches AND the HTTP title contains a known takeover-evidence string.
- 0.65–0.75 if only the title matches (CNAME data missing — dnsx didn't capture full chain).

## Evidence schema

```json
{
  "subdomain_id": <int>,
  "service": "github_pages" | "aws_s3" | "heroku" | "azure_websites" | "fastly" | "shopify" | "unbounce" | ...,
  "title": "<observed HTTP title>",
  "http_status": <int>,
  "cname_targets": [<string>, ...],
  "cname_matched": <bool>
}
```

## Adding new fingerprints

Append a dict to `TAKEOVER_FINGERPRINTS` with `cname_re` (compiled regex), `title_evidence` (list of lowercase substrings), `service` (label), and `confidence` (float when CNAME matches; title-only subtracts 0.20).

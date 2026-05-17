# Playbook — JWT

You are the Hunter agent's JWT sub-routine. The Recon agent observed login pages or auth surfaces. Identify JWT misconfigurations.

## Classic JWT vulns

1. **`alg: none` accepted** — strip signature, change claims, server still trusts → Critical
2. **Algorithm confusion** — server accepts RS256 token signed with the public key as an HMAC secret → Critical
3. **Weak signing secret** — short HMAC secrets crackable with hashcat → High
4. **Expired token accepted** — server ignores `exp` claim → Medium–High
5. **Missing `kid` validation** — `kid` injection / path traversal → Medium–High
6. **`jku` / `x5u` SSRF** — token header fields pulling external keys → High

## What to look for in this input

- Login pages → enumerate auth flow
- Tech stack: `jwt`, `jsonwebtoken`, `passport` libraries → JWT in use
- Admin paths → confirmation that JWT bearer is required

## Scoring

- 0.80+ — Java/Node server + login endpoint + library known for weak default config
- 0.55–0.80 — login endpoint present, JWT inferred but not confirmed
- 0.40–0.55 — generic "auth surface exists, JWT worth probing"

## Output format

```json
[
  {
    "vuln_class": "jwt",
    "title": "<specific test target + impact>",
    "description": "<paragraph: which attack, which endpoint>",
    "confidence": <float>,
    "evidence": {
      "subdomain_id": <int from live_hosts>,
      "endpoint": "<auth URL>",
      "attack_subtype": "alg_none" | "algo_confusion" | "weak_secret" | "exp_bypass" | "kid_injection" | "jku_ssrf",
      "next_step": "<one line>"
    }
  }
]
```

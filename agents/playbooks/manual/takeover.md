# Subdomain Takeover — Manual Verification

ReconForge detects takeover candidates deterministically (CNAME signature
+ title-content match). Manual step: prove you can serve content on the
hijacked subdomain.

- [ ] Confirm the CNAME points to a service that allows unauthenticated claim.
- [ ] Confirm the target service has no current owner (404 / "not found" / signature page).
- [ ] Register the resource on the third-party service (e.g. GitHub Pages, S3 bucket).
- [ ] Serve a benign proof file (researcher-controlled HTML with timestamp).
- [ ] Verify the proof is reachable via the victim subdomain.
- [ ] **Do not** serve phishing content, credential prompts, or anything else.
- [ ] Capture: CNAME chain, claim transaction, served-content screenshot.

**Severity uplift signals**
- Subdomain is in the auth cookie scope (→ session hijack).
- Subdomain hosts authentication / OAuth callbacks.
- Subdomain in any email-sender / DKIM context.

# XSS — Manual Verification (JS-context first)

Treat reflected HTML XSS as a starting point. The high-payout bugs are
JavaScript-context: parameters reflected into `<script>`, DOM sinks,
postMessage handlers.

- [ ] Identify the reflection context: HTML body, attribute, JS string,
      DOM sink (innerHTML / document.write / eval / location.hash).
- [ ] Note the CSP (if any) and any inline-script restrictions.
- [ ] Build a context-appropriate payload — don't rely on `<script>alert(1)`.
- [ ] Confirm execution in a real browser, not a curl dump.
- [ ] For DOM-based: trace the source → sink using DOM Invader or manual.
- [ ] For stored: confirm the payload persists across sessions / admin views.
- [ ] Capture browser-rendered evidence (screenshot + console output).
- [ ] If CSP blocks the payload, document the bypass primitive you needed.

**Severity uplift signals**
- Stored XSS in an admin-rendered view (→ admin session hijack).
- DOM XSS triggered without user interaction (no click required).
- Auth-context cookie accessible (no `HttpOnly`).
- Account takeover chain via session theft + CSRF.

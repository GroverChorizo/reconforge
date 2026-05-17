# XXE / XML External Entity — Manual Verification

ReconForge identifies XML-capable entry points. Verification stays manual
and authorized-only; we do not automate blind exfiltration.

- [ ] XML body accepted by the endpoint? Check Content-Type.
- [ ] Parser behavior observable through error messages or response body?
- [ ] External entities allowed (does the parser resolve `<!ENTITY ext SYSTEM "http://..">`)?
- [ ] Does the program brief allow out-of-band interaction (Interactsh)?
- [ ] File upload accepts XML-bearing formats (.docx, .xlsx, .svg, .saml)?
- [ ] Submit a benign payload first to confirm parser invocation.
- [ ] If OOB testing is permitted, use a researcher-controlled callback URL.
- [ ] Record the parser error / response that proves entity resolution.

**Severity uplift signals**
- File read of `/etc/passwd` or app config.
- SSRF chain (XXE → internal network).
- Blind exfiltration via parameter entities.

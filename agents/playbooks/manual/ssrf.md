# SSRF — Manual Verification

Identify URL-accepting parameters and webhook configurations. **Do not
scan internal networks. Do not automatically probe cloud metadata services.**

- [ ] Endpoint accepts a URL, URI, callback, or webhook parameter.
- [ ] Does the server appear to fetch the supplied URL (timing / response delta)?
- [ ] Program rules permit SSRF testing?
- [ ] Out-of-band callback testing permitted?
- [ ] Test with a researcher-controlled benign endpoint first (Interactsh / your own).
- [ ] Do not target `169.254.169.254`, `metadata.google.internal`, internal IPs,
      or other infrastructure unless explicitly allowed.
- [ ] Capture request + response showing the server initiated an outbound request.
- [ ] Record timestamp and OOB callback log.

**Severity uplift signals**
- Cloud metadata service reachable (→ credentials).
- Internal service banner returned in response.
- Filter bypass that crosses program-defined boundaries.

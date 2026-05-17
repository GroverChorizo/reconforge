# IDOR / Broken Object-Level Authorization — Manual Verification

Before claiming this finding, confirm with **researcher-owned accounts only**.
Never access third-party user data.

- [ ] Confirm both test accounts are authorized and owned by the researcher.
- [ ] Capture the request as Account A (use Burp / proxy).
- [ ] Identify the object identifier (numeric ID, UUID, slug).
- [ ] Replay the request as Account B, swapping the identifier to one
      belonging to Account A.
- [ ] Compare response status, body, and authorization behavior.
- [ ] Repeat with at least one more candidate identifier to rule out
      a one-off response.
- [ ] Record raw request + response pairs as evidence.
- [ ] If the endpoint mutates state, confirm the change persisted using
      Account A's session, not Account B's.

**Severity uplift signals**
- Cross-tenant access (Account A is in a different organization).
- Admin-scoped objects accessible to a standard user.
- PII / financial / private application data returned.

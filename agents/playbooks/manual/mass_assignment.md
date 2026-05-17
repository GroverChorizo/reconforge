# Mass Assignment / Excessive Parameter Binding — Manual Verification

The XSS Rat / Wesley Thijs "isAdmin:false" move. Look for fields the server
discloses in responses but doesn't expect in requests, then test whether
the server accepts client-supplied changes.

- [ ] Use only researcher-owned accounts.
- [ ] Identify a create or update endpoint that accepts a JSON body.
- [ ] Compare the response shape against the accepted request body.
- [ ] List response-only fields that look privileged: `isAdmin`, `role`,
      `permissions`, `plan`, `tier`, `verified`, `organizationId`,
      `ownerId`, `tenantId`, `balance`, `credit`, `isStaff`.
- [ ] Add **one** candidate field at a time to the request body.
- [ ] Use harmless values first (`role: "test"`), escalate only after the
      server accepts the field.
- [ ] Verify whether the server stores, reflects, or acts on the field.
- [ ] Capture before / after evidence (response + database read if possible).
- [ ] Do not modify privileges unless explicitly allowed and only on
      researcher-owned test accounts.

**Severity uplift signals**
- Role / privilege escalation on owned account.
- Cross-tenant manipulation.
- Billing / balance changes.

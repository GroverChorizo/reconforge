# {{title}}

## Summary
An object-level authorization weakness allows a user to access or modify
resources that should belong to another account or tenant.

## Affected Asset
- Program: {{program_name}}
- URL: {{asset}}
- Endpoint: {{endpoint}}
- Method: {{method}}
- Parameter: {{parameter}}
- Object type: {{object_type}}

## Severity
{{severity}} — CVSS 4.0 vector: {{cvss_vector}}

## Weakness Classification
- CWE-639 Authorization Bypass Through User-Controlled Key
- CWE-284 Improper Access Control
- OWASP A01:2021 Broken Access Control

## Preconditions
- Researcher-controlled Account A: {{account_a}}
- Researcher-controlled Account B: {{account_b}}

## Steps to Reproduce
1. Log in as Account A.
2. Capture the request to access Account A's resource ({{object_type}} ID
   `{{object_a}}`).
3. Replace the object identifier with `{{object_b}}` — the equivalent
   identifier from Account B.
4. Replay the request using Account A's session.
5. Observe the response returns or modifies Account B's resource without
   the expected authorization check.

## Evidence
{{evidence}}

## Impact
{{impact}}

## Remediation
Enforce server-side object-level authorization checks for every request.
Do not rely on client-side controls or assume identifiers are unguessable.
Validate that the authenticated user owns or has explicit permission for
the requested object before returning or mutating it.

## Researcher Notes
{{notes}}

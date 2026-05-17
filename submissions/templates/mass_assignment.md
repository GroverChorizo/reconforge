# {{title}}

## Summary
The application accepts client-supplied fields that should be controlled
exclusively by the server. The vulnerable endpoint binds incoming JSON
keys directly to backing objects, allowing a user to set fields not
exposed in the public request schema.

## Affected Asset
- Program: {{program_name}}
- URL: {{asset}}
- Endpoint: {{endpoint}}
- Method: {{method}}
- Vulnerable field: `{{field}}`

## Severity
{{severity}} — CVSS 4.0 vector: {{cvss_vector}}

## Weakness Classification
- CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-284 Improper Access Control
- OWASP A01:2021 Broken Access Control
- OWASP A04:2021 Insecure Design

## Steps to Reproduce
1. Authenticate as a researcher-controlled standard-privilege account.
2. Capture a normal update or create request for `{{endpoint}}`.
3. Inject the field `{{field}}` (observed in `{{response_source}}` responses
   but absent from accepted request schemas).
4. Submit the modified request.
5. Observe the server accepts the field and the change is reflected in
   subsequent reads.

## Evidence
{{evidence}}

## Impact
{{impact}}

## Remediation
Use explicit server-side allowlists for bindable fields (DTO whitelist /
schema validator). Reject or silently strip sensitive fields from client
input. The vulnerable mass-assignment surface should be replaced with an
explicit set of accepted parameters per endpoint.

## Researcher Notes
{{notes}}

# {{title}}

## Summary
The application makes server-side requests to user-controlled URLs without
sufficient validation. {{ssrf_impact_summary}}

## Affected Asset
- Program: {{program_name}}
- URL: {{asset}}
- Endpoint: {{endpoint}}
- Method: {{method}}
- Vulnerable parameter: `{{parameter}}`

## Severity
{{severity}} — CVSS 4.0 vector: {{cvss_vector}}

## Weakness Classification
- CWE-918 Server-Side Request Forgery
- OWASP A10:2021 Server-Side Request Forgery

## Steps to Reproduce
1. Submit a researcher-controlled URL `{{oob_url}}` in the `{{parameter}}`
   parameter.
2. Observe the server initiates an outbound request to `{{oob_url}}`
   (timestamp, headers, source IP captured at the OOB endpoint).
3. {{additional_steps}}

## Evidence
{{evidence}}

## Impact
{{impact}}

## Remediation
Validate and allowlist destinations: parse the user-supplied URL, resolve
DNS in advance, and reject private/internal IP ranges before initiating
the request. Block redirects to disallowed destinations. Isolate
server-side fetchers from internal infrastructure (egress firewall,
dedicated fetcher service).

## Researcher Notes
{{notes}}

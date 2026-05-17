# {{title}}

## Summary
The application processes XML input in a way that allows unsafe external
entity resolution or related XML parser behavior.

## Affected Asset
- Program: {{program_name}}
- URL: {{asset}}
- Endpoint: {{endpoint}}
- Method: {{method}}
- Content-Type: {{content_type}}

## Severity
{{severity}} — CVSS 4.0 vector: {{cvss_vector}}

## Weakness Classification
- CWE-611 Improper Restriction of XML External Entity Reference
- OWASP A05:2021 Security Misconfiguration

## Steps to Reproduce
1. Submit the benign XML document at `{{benign_payload}}` to confirm the
   endpoint parses XML.
2. Submit the authorized test payload at `{{xxe_payload}}` demonstrating
   external entity resolution.
3. Observe the server response (or approved out-of-band callback) confirms
   the entity was resolved.
4. Record the parser-leaked content / OOB log entry.

## Evidence
{{evidence}}

## Impact
{{impact}}

## Remediation
Disable external entity resolution on the XML parser. For Java JAXP /
.NET XmlReader / Python lxml / libxml2: explicitly set the parser to
reject DOCTYPE declarations and external entities. Use hardened parser
configurations as recommended by OWASP XXE Prevention Cheat Sheet.

## Researcher Notes
{{notes}}

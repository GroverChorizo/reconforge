# {{title}}

## Summary
A user-controlled input is reflected or processed in an unsafe browser
execution context, allowing script execution under {{trigger_conditions}}.

## Affected Asset
- Program: {{program_name}}
- URL: {{asset}}
- Parameter: `{{parameter}}`
- Reflection context: {{reflection_context}}
- Authentication required: {{auth_required}}

## Severity
{{severity}} — CVSS 4.0 vector: {{cvss_vector}}

## Weakness Classification
- CWE-79 Improper Neutralization of Input During Web Page Generation
- OWASP A03:2021 Injection

## Steps to Reproduce
1. Navigate to `{{asset}}`.
2. Supply the test input `{{payload}}` in the `{{parameter}}` parameter.
3. Observe the input is rendered in the {{reflection_context}} context
   without appropriate encoding / sanitization.
4. Confirm script execution in a browser ({{browser}}).

## Evidence
{{evidence}}

## Impact
{{impact}}

## Remediation
Encode output according to context: HTML entity-encode in HTML body,
JavaScript-encode in script blocks, URL-encode in URLs. Avoid unsafe DOM
sinks (`innerHTML`, `document.write`, `eval`, `setTimeout` with string).
Enforce a Content Security Policy that restricts inline scripts and
external script sources.

## Researcher Notes
{{notes}}

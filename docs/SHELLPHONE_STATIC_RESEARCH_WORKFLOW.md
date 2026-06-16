# Shellphone Static Research Workflow

This workflow converts the Church of Malware article `Our Blessed Connection — The Shellphone Sermon` into ReconForge-native defensive research, static artifact triage, mitigation mapping, and reporting notes.

## Safety boundary

ReconForge may catalog exploit-development concepts, review imported local artifacts, map mitigations, and draft defensive reports. It must not generate shellcode, build encoders, construct ROP chains, run payloads, perform process injection, open listeners, deploy loaders, create reverse shells, or automate bypasses.

The workflow is static-first:

- The article is taxonomy/reference material.
- Binary/crash/source artifacts must be imported locally.
- Local analysis is read-only and evidence-oriented.
- No payload generation or execution is allowed.
- No live target traffic is required by default.

## Workflow ID

`shellphone_static_research`

## Default safety envelope

- Mode: `evidence_collection`
- Traffic level: `none`
- Default rate limit: `0`
- Imported artifact mode: `true`
- Reference-only mode: `true`
- Scope required: `false` by default for imported local artifacts

## Inputs

- `reference_article_url`
- `binary_sample`
- `strings_output`
- `crash_log`
- `sandbox_notes`
- `edr_alerts`
- `mitigation_flags`
- `local_source_snapshot`

## Outputs

- `shellphone_static_summary.json`
- `exploit_dev_detection_notes.md`
- `mitigation_mapping.json`
- `artifact_triage_notes.md`
- `evidence_bundle/`

## Research tools

| Tool | Purpose | Execution policy |
|:---|:---|:---|
| `shellphone_reference_catalog` | Catalog article concepts as defensive exploit-dev taxonomy | Reference only; no execution |
| `encoded_artifact_triage` | Review local notes/artifacts for encoded or staged-content indicators | Local static notes only; no decode/execute/transform |
| `binary_strings_triage` | Run local strings extraction on imported artifacts | Local artifact only; no network; no execution |
| `memory_behavior_checklist` | Build a process-injection-like telemetry checklist | Checklist only; no process injection |
| `exploit_mitigation_mapper` | Map observations to mitigations and defensive controls | Mitigation mapping only |
| `exploit_dev_report_notes` | Draft defensive report notes with disclaimers | Reporting only; no payload execution |
| `mitre_attack_mapper` | Map observations to ATT&CK-style taxonomy | Reference only |

## Defensive taxonomy

Use the article as a source for defensive labels, not implementation:

- Shellcode and loader concepts become static-analysis labels.
- Encoder/packed/staged-content concepts become artifact-triage labels.
- Process-injection concepts become EDR/event-log review questions.
- ASLR/DEP/NX/CFG references become mitigation-mapping fields.
- Crash notes and sandbox observations become report evidence, not exploit steps.

## ATT&CK-style mapping panel

- `T1055` Process Injection — used as a defensive telemetry bucket.
- `T1027` Obfuscated/Compressed Files and Information — used for encoded/packed/staged-content review.
- `T1068` Exploitation for Privilege Escalation — used only as an exploit-dev risk context label.
- `T1106` Native API — used for suspicious native API behavior notes, not API-calling automation.

## Evidence questions

1. Does the imported artifact contain suspicious strings, imports, or section metadata?
2. Does the crash/sandbox note mention memory allocation, memory protection, unusual module loading, or thread-start anomalies?
3. Are mitigations such as ASLR, DEP/NX, CFG, code signing, sandboxing, or EDR controls present or absent?
4. Are encoded, packed, or staged-content indicators present without legitimate installer/update context?
5. Is there enough evidence to write defensive detection notes without reproducing the payload?

## Report disclaimer

Every report generated from this workflow should include:

> ReconForge did not generate shellcode, build encoders, construct ROP chains, run payloads, perform process injection, open listeners, deploy loaders, create reverse shells, or automate bypasses. This report is based on authorized reference review and/or imported local static artifacts.

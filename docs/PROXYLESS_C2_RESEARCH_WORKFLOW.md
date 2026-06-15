# Proxyless C2 Research Workflow

This workflow converts Church-of-Malware-style C2 references and imported lab telemetry into ReconForge-native taxonomy, detection notes, evidence bundles, and ATT&CK mapping.

## Safety boundary

ReconForge may catalog C2 concepts, review local artifacts, and draft defensive reports. It must not deploy, operate, generate, or test any C2 payload, listener, implant, persistence mechanism, reverse shell, bind shell, credential-theft workflow, or public callback infrastructure.

The workflow is research-first:

- Church repositories are taxonomy/reference material.
- Claude bug-bounty documentation is methodology/reference material.
- Local telemetry can be imported for defensive review.
- Live target traffic remains scoped and approval-gated elsewhere.

## Workflow ID

`proxyless_c2_research`

## Default safety envelope

- Mode: `evidence_collection`
- Traffic level: `none`
- Default rate limit: `0`
- Imported artifact mode: `true`
- Reference-only mode: `true`
- Scope required for live targets: `true`

## Inputs

- `pcap_file`
- `zeek_log_dir`
- `suricata_eve_json`
- `dns_logs`
- `http_logs`
- `tls_logs`
- `target_scope`
- `lab_notes`
- `reference_repo_url`

## Outputs

- `proxyless_c2_summary.json`
- `proxyless_c2_detection_notes.md`
- `mitre_attack_mapping.json`
- `evidence_bundle/`
- `reference_taxonomy.json`

## Research tools

| Tool | Purpose | Execution policy |
|:---|:---|:---|
| `church_reference_catalog` | Catalog Church repositories as taxonomy/reference objects | Reference only; no execution |
| `tshark_pcap_summary` | Summarize local PCAP flow telemetry | Local artifact only; no network |
| `zeek_pcap_analyze` | Generate local Zeek logs from imported PCAPs | Local artifact only; no network |
| `suricata_eve_review` | Review imported Suricata `eve.json` telemetry | Local artifact only; no network |
| `sigma_c2_log_hunt` | Apply Sigma-style C2 detection concepts to local logs | Local artifact only; no network |
| `c2_ioc_extractor_static` | Extract IOCs from notes/source/README snapshots | Local static analysis only |
| `mitre_attack_mapper` | Map evidence to ATT&CK | Reference only; no execution |

## ATT&CK panel

- `TA0011` Command and Control
- `T1071` Application Layer Protocol
- `T1071.001` Web Protocols
- `T1090` Proxy as comparison / negative-control
- `T1105` Ingress Tool Transfer as evidence-only telemetry

## Direct-vs-proxied C2 evidence questions

Use imported telemetry to answer:

1. Does the client connect directly to infrastructure associated with the suspected controller?
2. Is there evidence of intermediary proxy infrastructure, CDN fronting, redirectors, or commodity hosting layers?
3. Are there beaconing intervals, stable URI paths, repeated headers, anomalous SNI, or suspicious DNS cadence?
4. Are flows one-to-one, many-to-one, bursty, periodic, or event-driven?
5. Can false positives be explained by legitimate update checks, telemetry clients, monitoring agents, or normal SaaS traffic?

## Report disclaimer

Every report generated from this workflow should include:

> ReconForge did not deploy, operate, generate, or test any C2 payload, listener, implant, persistence mechanism, reverse shell, bind shell, credential-theft workflow, or callback infrastructure. This report is based on authorized taxonomy review and/or imported local telemetry.

## Claude bug-bounty methodology notes

The `shuvonsec/claude-bug-bounty` docs are used as methodology references only. The docs include advanced bug-bounty chaining, auth/session management, curated payload references, and smart-contract audit notes. ReconForge converts those into checklist, taxonomy, and evidence workflows; it does not import payloads as executable modules.

"""Workflow primitives.

A *workflow* is a named bundle of (mode, tools, safety) the operator
selects when creating a job. Baseline workflows remain hardcoded here so the
pre-flight endpoint, mode selector, and command-preview component have a stable
API while the YAML loader evolves.

Public surface:
  list_workflows() -> list[Workflow]
  get_workflow(workflow_id) -> Workflow | None
  workflows_for_mode(mode) -> list[Workflow]
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from tools import registry as _registry


@dataclass
class WorkflowToolStep:
    """A single tool invocation declared by a workflow."""
    id: str                       # tool name in tools.registry.REGISTRY
    description: str = ""
    optional: bool = False        # workflow is still considered "complete" without it


@dataclass
class WorkflowSafety:
    """Safety envelope a workflow advertises to the operator."""
    traffic_level: str            # "none" | "low" | "moderate" | "intrusive"
    default_rate_limit_rps: Optional[int] = None
    blocked_if_scope_unknown: bool = True


@dataclass
class Workflow:
    id: str
    name: str
    mode: str                     # one of tools.registry.OPERATOR_MODES
    description: str
    requires_approval: bool       # operator must confirm before run
    scope_required: bool          # ScopeGuard must pass before live tool dispatch
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    tools: List[WorkflowToolStep] = field(default_factory=list)
    safety: WorkflowSafety = field(default_factory=lambda: WorkflowSafety("low"))
    imported_artifact_mode: bool = False
    reference_only: bool = False
    guardrail: str = ""
    attack_mapping: List[str] = field(default_factory=list)
    source_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def tool_names(self) -> List[str]:
        return [t.id for t in self.tools]


# ── baseline workflows ────────────────────────────────────────────
_BASELINES: List[Workflow] = [
    Workflow(
        id="passive_recon",
        name="Passive Recon",
        mode="passive_recon",
        description=(
            "Discover assets using OSINT and certificate-transparency sources. "
            "Zero traffic to the target. Foundation for every engagement."
        ),
        requires_approval=False,
        scope_required=True,
        inputs=["root_domain"],
        outputs=["subdomains", "assets"],
        tools=[
            WorkflowToolStep(id="subfinder",   description="Passive subdomain enumeration."),
            WorkflowToolStep(id="assetfinder", description="Tomnomnom OSINT enumeration."),
            WorkflowToolStep(id="amass",       description="OWASP Amass passive mode."),
            WorkflowToolStep(id="crtsh",       description="Certificate Transparency log search."),
            WorkflowToolStep(id="findomain",   description="Cross-platform subdomain enumerator."),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=True,
        ),
    ),
    Workflow(
        id="active_recon",
        name="Active Recon",
        mode="active_recon",
        description=(
            "Resolve discovered hostnames and probe live HTTP services. "
            "Single-request probes, conservative concurrency."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=["subdomains"],
        outputs=["live_hosts", "screenshots", "tech_fingerprints"],
        tools=[
            WorkflowToolStep(id="dnsx",      description="Resolve hostnames + record IPs."),
            WorkflowToolStep(id="httpx",     description="HTTP probe + tech fingerprint."),
            WorkflowToolStep(id="gowitness", description="Live-host screenshots."),
            WorkflowToolStep(id="wafw00f",   description="WAF fingerprint."),
        ],
        safety=WorkflowSafety(
            traffic_level="low",
            default_rate_limit_rps=10,
            blocked_if_scope_unknown=True,
        ),
    ),
    Workflow(
        id="content_discovery",
        name="Content Discovery",
        mode="content_discovery",
        description=(
            "Discover routes, endpoints, and API surfaces. Requires explicit "
            "operator approval before run."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=["live_hosts"],
        outputs=["endpoints"],
        tools=[],
        safety=WorkflowSafety(
            traffic_level="moderate",
            default_rate_limit_rps=25,
            blocked_if_scope_unknown=True,
        ),
    ),
    Workflow(
        id="vuln_triage",
        name="Vulnerability Triage",
        mode="vuln_triage",
        description=(
            "Template-based vuln scanning. Conservative severity filter; "
            "high/critical results require manual verification."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=["live_hosts"],
        outputs=["finding_candidates"],
        tools=[
            WorkflowToolStep(id="nuclei",       description="Templated vuln scan."),
            WorkflowToolStep(id="graphw00f",    description="GraphQL fingerprint (adaptive).",
                              optional=True),
            WorkflowToolStep(id="clairvoyance", description="GraphQL schema rebuild (adaptive).",
                              optional=True),
            WorkflowToolStep(id="inql",         description="GraphQL query/mutation enum (adaptive).",
                              optional=True),
            WorkflowToolStep(id="s3scanner",    description="Bucket access probe (adaptive).",
                              optional=True),
        ],
        safety=WorkflowSafety(
            traffic_level="moderate",
            default_rate_limit_rps=25,
            blocked_if_scope_unknown=True,
        ),
    ),
    Workflow(
        id="evidence_collection",
        name="Evidence Collection",
        mode="evidence_collection",
        description=(
            "Operator-driven evidence capture. Intrusive tools allowed only "
            "with explicit scope acknowledgement."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=["finding_candidates"],
        outputs=["evidence_artifacts"],
        tools=[],   # operator selects per-finding
        safety=WorkflowSafety(
            traffic_level="moderate",
            default_rate_limit_rps=50,
            blocked_if_scope_unknown=True,
        ),
    ),

    # ── Church / Claude bug-bounty methodology workflows ───────────
    Workflow(
        id="proxyless_c2_research",
        name="Proxyless C2 Research",
        mode="evidence_collection",
        description=(
            "Catalog Church-of-Malware-style proxyless/direct-C2 references, "
            "analyze imported lab telemetry, and produce defensive ATT&CK-mapped "
            "reports without launching C2 infrastructure, listeners, payloads, "
            "implants, reverse shells, persistence, or callbacks."
        ),
        requires_approval=True,
        scope_required=True,
        imported_artifact_mode=True,
        reference_only=True,
        inputs=[
            "pcap_file", "zeek_log_dir", "suricata_eve_json", "dns_logs",
            "http_logs", "tls_logs", "target_scope", "lab_notes",
            "reference_repo_url",
        ],
        outputs=[
            "proxyless_c2_summary.json", "proxyless_c2_detection_notes.md",
            "mitre_attack_mapping.json", "evidence_bundle/",
            "reference_taxonomy.json",
        ],
        tools=[
            WorkflowToolStep(id="church_reference_catalog", description="Catalog Church repositories as taxonomy/reference material only."),
            WorkflowToolStep(id="tshark_pcap_summary", description="Summarize local PCAP flow/transport telemetry.", optional=True),
            WorkflowToolStep(id="zeek_pcap_analyze", description="Generate local Zeek logs from imported PCAPs.", optional=True),
            WorkflowToolStep(id="suricata_eve_review", description="Review imported Suricata eve.json telemetry.", optional=True),
            WorkflowToolStep(id="sigma_c2_log_hunt", description="Apply Sigma-style C2 log-hunt concepts to local logs.", optional=True),
            WorkflowToolStep(id="c2_ioc_extractor_static", description="Extract IOCs from local notes/source/readmes without executing referenced tools."),
            WorkflowToolStep(id="mitre_attack_mapper", description="Map evidence to ATT&CK TA0011/T1071/T1090/T1105."),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=True,
        ),
        guardrail=(
            "Authorized malware-research taxonomy, local telemetry analysis, and defensive reporting only. "
            "ReconForge will not launch C2 servers, implants, payloads, reverse shells, persistence, listeners, or callbacks."
        ),
        attack_mapping=["TA0011", "T1071", "T1071.001", "T1090", "T1105"],
        source_refs=[
            "https://churchofmalware.org/",
            "https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs",
        ],
    ),
    Workflow(
        id="shellphone_static_research",
        name="Shellphone Static Research",
        mode="evidence_collection",
        description=(
            "Convert the Shellphone Sermon / Windows shellcode article into static defensive research: "
            "catalog exploit-dev concepts, review imported local artifacts, map mitigations, and draft "
            "evidence notes without generating shellcode, encoders, payloads, ROP chains, loaders, "
            "process injection, reverse shells, or bypass automation."
        ),
        requires_approval=True,
        scope_required=False,
        imported_artifact_mode=True,
        reference_only=True,
        inputs=[
            "reference_article_url", "binary_sample", "strings_output", "crash_log",
            "sandbox_notes", "edr_alerts", "mitigation_flags", "local_source_snapshot",
        ],
        outputs=[
            "shellphone_static_summary.json", "exploit_dev_detection_notes.md",
            "mitigation_mapping.json", "artifact_triage_notes.md", "evidence_bundle/",
        ],
        tools=[
            WorkflowToolStep(id="shellphone_reference_catalog", description="Catalog Shellphone concepts as defensive exploit-dev taxonomy only."),
            WorkflowToolStep(id="encoded_artifact_triage", description="Review local static artifacts for encoded/staged-content indicators without decode or execution."),
            WorkflowToolStep(id="binary_strings_triage", description="Extract local strings from imported artifacts for defensive triage.", optional=True),
            WorkflowToolStep(id="memory_behavior_checklist", description="Create process-injection-like telemetry checklist without injecting into processes."),
            WorkflowToolStep(id="exploit_mitigation_mapper", description="Map observations to ASLR/DEP/NX/CFG/signing/sandbox/EDR mitigations."),
            WorkflowToolStep(id="exploit_dev_report_notes", description="Draft defensive report notes with no-payload/no-execution disclaimer."),
            WorkflowToolStep(id="mitre_attack_mapper", description="Map notes to ATT&CK T1055/T1027/T1068/T1106.", optional=True),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=False,
        ),
        guardrail=(
            "Static exploit-development research only. ReconForge will not generate shellcode, build encoders, "
            "construct ROP chains, run payloads, perform process injection, open listeners, or automate bypasses."
        ),
        attack_mapping=["T1055", "T1027", "T1068", "T1106"],
        source_refs=["https://churchofmalware.org/articles/Our_Blessed_Connection_md"],
    ),
    Workflow(
        id="bug_chain_cluster_hunt",
        name="Bug Chain Cluster Hunt",
        mode="vuln_triage",
        description=(
            "Convert one confirmed finding into neighboring A→B→C hypotheses, "
            "sibling endpoint checks, evidence tasks, and separate report drafts. "
            "Inspired by claude-bug-bounty's cluster-hunt methodology; implemented "
            "as checklist/taxonomy work, not exploit automation."
        ),
        requires_approval=True,
        scope_required=True,
        reference_only=True,
        inputs=["confirmed_finding", "affected_module", "sibling_endpoints", "evidence_artifacts"],
        outputs=["chain_hypotheses", "sibling_test_plan", "impact_matrix", "report_queue"],
        tools=[
            WorkflowToolStep(id="bug_chain_mapper", description="Map confirmed bug A to plausible B/C follow-up checks."),
            WorkflowToolStep(id="framework_signal_mapper", description="Add framework-specific sibling checks where applicable.", optional=True),
            WorkflowToolStep(id="mitre_attack_mapper", description="Map evidence and impact to report taxonomy.", optional=True),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=True,
        ),
        guardrail="Checklist/evidence workflow only; no payload execution or unauthorized data access.",
        source_refs=["https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs/advanced-techniques.md"],
    ),
    Workflow(
        id="framework_signal_review",
        name="Framework Signal Review",
        mode="vuln_triage",
        description=(
            "Build a framework-aware review plan for Next.js, Laravel, Spring Boot, "
            "Django, Rails, WordPress, GraphQL, mobile apps, and CI/CD surfaces. "
            "The workflow captures safe checks, negative cases, and evidence needs."
        ),
        requires_approval=True,
        scope_required=True,
        reference_only=True,
        inputs=["live_hosts", "tech_fingerprints", "source_notes", "auth_context"],
        outputs=["framework_checklist", "signal_matrix", "evidence_requirements"],
        tools=[
            WorkflowToolStep(id="framework_signal_mapper", description="Map detected technology to review checklist."),
            WorkflowToolStep(id="auth_session_checklist", description="Normalize auth/session prerequisites and evidence boundaries.", optional=True),
            WorkflowToolStep(id="payload_reference_triage", description="Use payload references as non-executable labeling guidance.", optional=True),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=True,
        ),
        guardrail="Reference workflow only; live probes remain gated by scoped workflows and operator approval.",
        source_refs=[
            "https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs/advanced-techniques.md",
            "https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs/auth-sessions.md",
            "https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs/payloads.md",
        ],
    ),
    Workflow(
        id="smart_contract_static_review",
        name="Smart Contract Static Review",
        mode="vuln_triage",
        description=(
            "Turn imported smart-contract source/artifacts into a static audit checklist, "
            "risk taxonomy, and evidence plan. No chain interaction is performed by default."
        ),
        requires_approval=True,
        scope_required=False,
        imported_artifact_mode=True,
        reference_only=True,
        inputs=["contract_source", "abi", "deployment_notes", "audit_scope"],
        outputs=["contract_static_checklist", "risk_notes", "evidence_requirements"],
        tools=[
            WorkflowToolStep(id="smart_contract_static_triage", description="Create local/static contract review checklist."),
            WorkflowToolStep(id="mitre_attack_mapper", description="Map observations to report taxonomy where useful.", optional=True),
        ],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=False,
        ),
        guardrail="Local/static analysis only; no transaction crafting or chain interaction by default.",
        source_refs=["https://github.com/shuvonsec/claude-bug-bounty/tree/main/docs/smart-contract-audit.md"],
    ),

    Workflow(
        id="report_drafting",
        name="Report Drafting",
        mode="report_drafting",
        description=(
            "Compose per-platform submission drafts from confirmed findings. "
            "No traffic to target."
        ),
        requires_approval=False,
        scope_required=False,
        inputs=["findings"],
        outputs=["submission_drafts"],
        tools=[],
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
            blocked_if_scope_unknown=False,
        ),
    ),
    Workflow(
        id="retest",
        name="Retest",
        mode="retest",
        description=(
            "Verify whether a previously confirmed finding has been fixed. "
            "Repeats only the original passive checks against the original asset."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=["finding_id"],
        outputs=["retest_result"],
        tools=[],   # determined per finding
        safety=WorkflowSafety(
            traffic_level="low",
            default_rate_limit_rps=5,
            blocked_if_scope_unknown=True,
        ),
    ),
]


# ── registry ──────────────────────────────────────────────────────
WORKFLOW_REGISTRY: Dict[str, Workflow] = {w.id: w for w in _BASELINES}


def list_workflows() -> List[Workflow]:
    """All registered workflows in declaration order."""
    return list(WORKFLOW_REGISTRY.values())


def get_workflow(workflow_id: str) -> Optional[Workflow]:
    return WORKFLOW_REGISTRY.get(workflow_id)


def workflows_for_mode(mode: str) -> List[Workflow]:
    return [w for w in WORKFLOW_REGISTRY.values() if w.mode == mode]


def validate_workflow_against_mode(workflow_id: str) -> List[str]:
    """Return tool names in the workflow that are not in its default mode set.

    Empty list means the workflow is consistent with its advisory default set.
    """
    w = get_workflow(workflow_id)
    if w is None:
        return []
    bad: List[str] = []
    for step in w.tools:
        if not _registry.is_tool_allowed_in_mode(step.id, w.mode):
            bad.append(step.id)
    return bad

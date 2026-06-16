"""Workflow primitives (Phase 15).

A *workflow* is a named bundle of (mode, tools, safety) the operator
selects when creating a job. Phase 15 ships the 7 hardcoded baselines —
one per operator mode in :data:`tools.registry.OPERATOR_MODES`. Phase 21
will swap the in-memory ``WORKFLOW_REGISTRY`` for a YAML loader without
changing this module's public API.

Why a primitive now, not later
------------------------------
The pre-flight endpoint, mode selector, and command-preview component all
need a stable workflow concept. Building them against a YAML loader risks
churning when the loader ships. Building them against this dataclass keeps
the call sites stable through Phase 21.

Public surface (stable through Phase 21):
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
    scope_required: bool          # ScopeGuard must pass before tool dispatch
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    tools: List[WorkflowToolStep] = field(default_factory=list)
    safety: WorkflowSafety = field(default_factory=lambda: WorkflowSafety("low"))

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
        outputs=["endpoints", "parameters", "api_routes"],
        tools=[
            # crawl + historical URL mining (cheap, run first)
            WorkflowToolStep(id="katana",      description="Headless SPA-aware crawl."),
            WorkflowToolStep(id="gau",          description="Historical URLs (wayback/OTX/commoncrawl)."),
            WorkflowToolStep(id="waybackurls",  description="Wayback Machine URL mining.",
                              optional=True),
            WorkflowToolStep(id="hakrawler",    description="Fast crawl of in-scope hosts.",
                              optional=True),
            # active content discovery
            WorkflowToolStep(id="feroxbuster",  description="Recursive content/route brute-force."),
            WorkflowToolStep(id="ffuf",         description="Web fuzzer for content/parameters (FUZZ keyword).",
                              optional=True),
            WorkflowToolStep(id="dirsearch",    description="Path/extension content discovery.",
                              optional=True),
            # parameter discovery
            WorkflowToolStep(id="paramspider",  description="Mine parameters from archived URLs.",
                              optional=True),
            WorkflowToolStep(id="arjun",        description="Probe-based parameter discovery.",
                              optional=True),
            WorkflowToolStep(id="x8",           description="Hidden HTTP parameter discovery.",
                              optional=True),
            # API surface (adaptive — fire when a spec/route signal appears)
            WorkflowToolStep(id="kiterunner",    description="API route discovery from Swagger corpus.",
                              optional=True),
            WorkflowToolStep(id="swagger_jacker", description="OpenAPI/Swagger endpoint extraction.",
                              optional=True),
        ],
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
    # ── defensive C2 research ─────────────────────────────────────
    # Detection / taxonomy / evidence workflow around proxyless (direct)
    # C2 concepts. Analyses *local* artifacts (PCAP/Zeek/Suricata/logs) and
    # maps evidence to ATT&CK. It NEVER deploys, operates, or generates C2 —
    # core.research_guard enforces that at the behaviour level, and the tool
    # steps here are all local telemetry/taxonomy (zero target traffic).
    Workflow(
        id="proxyless_c2_research",
        name="Proxyless C2 Research",
        mode="evidence_collection",
        description=(
            "Authorized malware-research taxonomy, local telemetry analysis, and "
            "defensive reporting around proxyless/direct-C2 concepts. ReconForge "
            "may catalog C2 concepts and analyze local artifacts, but it will NOT "
            "launch C2 servers, implants, payloads, reverse shells, persistence, "
            "or callback infrastructure."
        ),
        requires_approval=True,
        scope_required=True,
        inputs=[
            "pcap_file", "zeek_log_dir", "suricata_eve_json", "dns_logs",
            "http_logs", "tls_logs", "target_scope", "lab_notes",
        ],
        outputs=[
            "proxyless_c2_summary.json", "proxyless_c2_detection_notes.md",
            "mitre_attack_mapping.json", "evidence_bundle/",
            "reference_taxonomy.json",
        ],
        tools=[],   # local telemetry analyzers; all default traffic_level "none"
        safety=WorkflowSafety(
            traffic_level="none",
            default_rate_limit_rps=0,
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
    """Return list of tool names in the workflow that are NOT allowed in its
    own mode. Used by tests + startup self-check to catch misconfigured
    baselines. Empty list = workflow is consistent.
    """
    w = get_workflow(workflow_id)
    if w is None:
        return []
    bad: List[str] = []
    for step in w.tools:
        if not _registry.is_tool_allowed_in_mode(step.id, w.mode):
            bad.append(step.id)
    return bad

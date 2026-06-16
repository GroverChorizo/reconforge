"""Research-only tool registrations.

These tools extend ``tools.registry`` without turning ReconForge into a C2 or
malware operator. They are intentionally taxonomy/local-artifact oriented and
are guarded by :mod:`core.research_guard` before any subprocess can run.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from core import research_guard
from tools import registry
from tools.runner import build_cmd, run_proc, which


_LOCAL_ARTIFACT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "Local artifact path to analyze, such as a PCAP, Zeek log, Suricata eve.json, Sigma rule, binary sample, crash log, or source snapshot.",
        }
    },
    "required": ["target"],
}

_REFERENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "Reference URL, taxonomy slug, ATT&CK technique ID, or local research note path.",
        }
    },
    "required": ["target"],
}


def _attach_research_metadata(
    spec: registry.ToolSpec,
    *,
    operation_type: str,
    network_policy: str,
    execution_policy: str,
) -> registry.ToolSpec:
    # ToolSpec is a normal dataclass without slots, so research metadata can be
    # attached without changing the legacy constructor or breaking older tests.
    spec.operation_type = operation_type
    spec.network_policy = network_policy
    spec.execution_policy = execution_policy
    return spec


def _run_research_note(spec: registry.ToolSpec, args: Dict[str, Any], ctx: registry.DispatchContext) -> registry.ToolResult:
    decision = research_guard.validate_tool_spec(spec)
    if not decision.allowed:
        return registry.ToolResult(
            spec.name,
            False,
            f"research guard blocked {spec.name}",
            error=decision.reason,
        )

    target = args.get("target") or args.get("domain") or "reference"
    return registry.ToolResult(
        spec.name,
        True,
        f"{spec.name}: research/taxonomy note recorded for {target}; no subprocess executed",
        items=[
            {
                "target": target,
                "operation_type": decision.operation_type,
                "network_policy": decision.network_policy,
                "execution_policy": getattr(spec, "execution_policy", "reference_only"),
            }
        ],
    )


def _run_local_artifact(spec: registry.ToolSpec, args: Dict[str, Any], ctx: registry.DispatchContext) -> registry.ToolResult:
    decision = research_guard.validate_tool_spec(spec)
    if not decision.allowed:
        return registry.ToolResult(
            spec.name,
            False,
            f"research guard blocked {spec.name}",
            error=decision.reason,
        )

    target = args.get("target") or args.get("path") or args.get("file")
    if not target:
        return registry.ToolResult(spec.name, False, "missing local artifact target", error="missing target")

    binary = (spec.cmd_template or "").split()[0]
    if not binary:
        return registry.ToolResult(spec.name, False, "missing command template", error="missing command")
    if not which(binary):
        return registry.ToolResult(spec.name, False, f"{binary}: binary not found", error="missing")

    os.makedirs(ctx.workdir, exist_ok=True)
    out = os.path.join(ctx.workdir, f"{spec.name}_output.txt")
    cmd = build_cmd(
        spec.cmd_template or "",
        {
            "$TARGET$": str(target),
            "$OUTPUT$": out,
            "$THREADS$": str(ctx.threads),
        },
    )
    rc, stdout, stderr = run_proc(cmd, timeout=spec.timeout, cancel_event=ctx.cancel_event)
    return registry.ToolResult(
        spec.name,
        ok=(rc == 0),
        rc=rc,
        summary=f"{spec.name}: local artifact analysis completed with rc={rc}",
        items=[stdout[:4000]] if stdout else [],
        raw_path=out if os.path.exists(out) else None,
        error=(stderr.strip() or None) if rc != 0 else None,
    )


def _register_research_tool(
    name: str,
    *,
    description: str,
    technique: str,
    handler: str,
    input_schema: Dict[str, Any],
    cmd_template: str | None = None,
    operation_type: str,
    network_policy: str,
    execution_policy: str,
    timeout: int = 600,
) -> None:
    spec = registry.ToolSpec(
        name=name,
        category="research",
        technique=technique,
        description=description,
        input_schema=input_schema,
        handler=handler,
        cmd_template=cmd_template,
        timeout=timeout,
        adaptive=True,
        safety_class="passive",
    )
    registry.REGISTRY[name] = _attach_research_metadata(
        spec,
        operation_type=operation_type,
        network_policy=network_policy,
        execution_policy=execution_policy,
    )


def register() -> None:
    registry._HANDLERS["research_note"] = _run_research_note
    registry._HANDLERS["local_artifact"] = _run_local_artifact

    _register_research_tool(
        "church_reference_catalog",
        description=(
            "Catalog Church-of-Malware-style repositories as defensive taxonomy/reference material. "
            "No tool execution; captures family/tool type, observed capabilities, defensive relevance, and ATT&CK mapping."
        ),
        technique="T1584",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="passive_intel_only",
        execution_policy="reference_only_no_execution",
    )
    _register_research_tool(
        "mitre_attack_mapper",
        description="Map workflow evidence and taxonomy notes to ATT&CK tactics/techniques for defensive reporting.",
        technique="T1071",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="reference_only_no_execution",
    )
    _register_research_tool(
        "c2_ioc_extractor_static",
        description="Extract C2-related IOCs from local notes, README text, logs, and source snapshots without launching referenced tooling.",
        technique="T1071",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
    )
    _register_research_tool(
        "tshark_pcap_summary",
        description="Summarize a local PCAP for flows, DNS, HTTP, TLS/SNI, JA3-like fields, and periodicity clues.",
        technique="T1071.001",
        handler="local_artifact",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        cmd_template="tshark -r $TARGET$ -q -z conv,tcp -z conv,udp",
        operation_type="local_telemetry_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
        timeout=1200,
    )
    _register_research_tool(
        "zeek_pcap_analyze",
        description="Run Zeek against a local PCAP to produce DNS/HTTP/SSL/connection logs for C2 detection review.",
        technique="T1071.001",
        handler="local_artifact",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        cmd_template="zeek -r $TARGET$ LogAscii::use_json=T",
        operation_type="local_telemetry_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
        timeout=1800,
    )
    _register_research_tool(
        "suricata_eve_review",
        description="Review a local Suricata eve.json artifact for malware/C2-relevant alert, DNS, HTTP, TLS, and flow records.",
        technique="T1071.001",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_telemetry_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
    )
    _register_research_tool(
        "sigma_c2_log_hunt",
        description="Apply Sigma-style C2 detection concepts to local logs and record candidate evidence paths.",
        technique="T1071",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
    )
    _register_research_tool(
        "bug_chain_mapper",
        description="Turn a confirmed bug into A→B→C cluster-hunt hypotheses, sibling endpoint checks, and report-ready evidence tasks.",
        technique="T1595",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="checklist_only_no_payload_execution",
    )
    _register_research_tool(
        "framework_signal_mapper",
        description="Map framework-specific findings into safe checklist items for Next.js, Laravel, Spring Boot, Django, Rails, WordPress, GraphQL, mobile, and CI/CD review.",
        technique="T1592",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="checklist_only_no_payload_execution",
    )
    _register_research_tool(
        "auth_session_checklist",
        description="Convert auth/session requirements into deterministic evidence-capture tasks without storing secrets or bypassing scope controls.",
        technique="T1078",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="checklist_only_no_secret_storage",
    )
    _register_research_tool(
        "payload_reference_triage",
        description="Use payload references as documentation for bug-class labeling and negative testing notes; never emit or execute live payloads.",
        technique="T1190",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="reference_only_no_payload_execution",
    )
    _register_research_tool(
        "smart_contract_static_triage",
        description="Create a local/static smart-contract audit checklist and evidence map from source artifacts.",
        technique="T1592",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network",
    )

    # ── Shellphone / exploit-dev defensive research additions ──────
    _register_research_tool(
        "shellphone_reference_catalog",
        description=(
            "Catalog Our Blessed Connection / Shellphone concepts as exploit-development taxonomy. "
            "Allowed use is documentation, defensive labeling, and mitigation mapping only; no shellcode generation or execution."
        ),
        technique="T1055",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="passive_intel_only",
        execution_policy="reference_only_no_shellcode_execution",
    )
    _register_research_tool(
        "exploit_mitigation_mapper",
        description=(
            "Map imported crash notes, binary metadata, or exploit-dev references to mitigations such as ASLR, DEP/NX, CFG, code signing, sandboxing, and EDR telemetry."
        ),
        technique="T1068",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="mitigation_mapping_only_no_exploit_building",
    )
    _register_research_tool(
        "encoded_artifact_triage",
        description=(
            "Review local notes or static artifacts for encoded/packed/staged-content indicators and document detection hypotheses. "
            "Does not decode, execute, emulate, or transform shellcode."
        ),
        technique="T1027",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_decode_execute_or_transform",
    )
    _register_research_tool(
        "binary_strings_triage",
        description="Run local strings extraction against a provided binary/log artifact to support defensive static triage notes.",
        technique="T1027",
        handler="local_artifact",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        cmd_template="strings -a $TARGET$",
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="local_artifact_only_no_network_no_execution",
        timeout=600,
    )
    _register_research_tool(
        "memory_behavior_checklist",
        description=(
            "Create a defensive checklist for process-injection-like telemetry: suspicious allocation/protection changes, cross-process handles, unusual thread starts, module-load anomalies, and parent/child process context."
        ),
        technique="T1055",
        handler="research_note",
        input_schema=_LOCAL_ARTIFACT_SCHEMA,
        operation_type="local_static_analysis",
        network_policy="none",
        execution_policy="checklist_only_no_process_injection",
    )
    _register_research_tool(
        "exploit_dev_report_notes",
        description=(
            "Draft report notes for exploit-dev references and local crash/artifact evidence, including defensive impact, mitigations, and an explicit no-payload/no-execution disclaimer."
        ),
        technique="T1068",
        handler="research_note",
        input_schema=_REFERENCE_SCHEMA,
        operation_type="taxonomy_only",
        network_policy="none",
        execution_policy="reporting_only_no_payload_execution",
    )


register()

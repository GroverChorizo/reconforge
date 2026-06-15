"""Research guardrails for malware-adjacent and C2-adjacent workflows.

ReconForge can catalog adversary tooling, import local telemetry, and produce
MITRE-mapped defensive reports. It must not become a runner for C2 servers,
implants, listeners, reverse shells, payload generation, persistence, or public
callback infrastructure.

This module is intentionally contextual: terminology such as "C2", "RAT",
"implant", or "botnet" is allowed in documentation and taxonomy. The guard
blocks execution behavior, unsafe operation types, unsafe network policies, and
unclassified research tool specs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional


ALLOWED_OPERATION_TYPES: frozenset[str] = frozenset({
    "taxonomy_only",
    "local_static_analysis",
    "local_telemetry_analysis",
    "passive_intel_lookup",
    "scoped_live_probe",
})

BLOCKED_OPERATION_TYPES: frozenset[str] = frozenset({
    "blocked_execution",
    "c2_server",
    "payload_generation",
    "implant_generation",
    "reverse_shell",
    "bind_shell",
    "persistence",
})

ALLOWED_NETWORK_POLICIES: frozenset[str] = frozenset({
    "none",
    "passive_intel_only",
    "local_lab_only",
    "scoped_target_only",
})

BLOCKED_NETWORK_POLICIES: frozenset[str] = frozenset({"blocked", "public_callback"})

# Command-template patterns only. These are not applied to descriptions,
# taxonomy notes, ATT&CK mappings, or report prose.
UNSAFE_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bmsfvenom\b",
        r"\bmeterpreter\b",
        r"\bexploit/multi/handler\b",
        r"\bmulti/handler\b",
        r"\bnc\s+-[^\s]*l[^\s]*\b",
        r"\bnc\s+.*\s-l\b",
        r"\bncat\s+-[^\s]*l[^\s]*\b",
        r"\bncat\s+.*\s-l\b",
        r"\bsocat\b.*\b(listen|fork)\b",
        r"\blisten(?:er)?\b.*\b(0\.0\.0\.0|::|tcp|http)\b",
        r"\breverse[-_\s]?shell\b",
        r"\bbind[-_\s]?shell\b",
        r"\bshellcode\b",
        r"\b(payload|implant)\b.*\b(generate|build|compile|create|emit)\b",
        r"\b(generate|build|compile|create|emit)\b.*\b(payload|implant)\b",
        r"\b(c2|command[-_\s]?and[-_\s]?control)\b.*\b(server|listener|callback)\b",
        r"\b(server|listener|callback)\b.*\b(c2|command[-_\s]?and[-_\s]?control)\b",
        r"\b(persistence|autorun|run\s+key|schtasks|crontab)\b",
        r"\bcredential[-_\s]?(dump|theft|steal|harvest)\b",
    )
)


@dataclass(frozen=True)
class ResearchGuardDecision:
    allowed: bool
    reason: str
    operation_type: str = ""
    network_policy: str = ""


def _first_matching_pattern(command_template: str) -> Optional[str]:
    for pattern in UNSAFE_COMMAND_PATTERNS:
        if pattern.search(command_template or ""):
            return pattern.pattern
    return None


def validate_operation(
    *,
    operation_type: str,
    network_policy: str,
    command_template: str = "",
    tool_id: str = "",
) -> ResearchGuardDecision:
    """Validate a research-tool execution context.

    This function evaluates execution metadata and command templates. It does
    not inspect prose fields; words such as C2, RAT, implant, botnet, and
    malware remain valid in defensive taxonomy and report writing.
    """
    op = (operation_type or "").strip()
    net = (network_policy or "").strip()

    if not op or not net:
        return ResearchGuardDecision(
            False,
            f"{tool_id or 'tool'} missing research safety metadata",
            op,
            net,
        )

    if op in BLOCKED_OPERATION_TYPES:
        return ResearchGuardDecision(False, f"blocked operation_type={op!r}", op, net)

    if net in BLOCKED_NETWORK_POLICIES:
        return ResearchGuardDecision(False, f"blocked network_policy={net!r}", op, net)

    if op not in ALLOWED_OPERATION_TYPES:
        return ResearchGuardDecision(False, f"unknown operation_type={op!r}", op, net)

    if net not in ALLOWED_NETWORK_POLICIES:
        return ResearchGuardDecision(False, f"unknown network_policy={net!r}", op, net)

    matched = _first_matching_pattern(command_template)
    if matched:
        return ResearchGuardDecision(
            False,
            f"unsafe command template matched research guard pattern: {matched}",
            op,
            net,
        )

    return ResearchGuardDecision(True, "research operation allowed", op, net)


def validate_tool_spec(spec: object) -> ResearchGuardDecision:
    """Validate a registry ToolSpec-like object with research metadata."""
    return validate_operation(
        operation_type=getattr(spec, "operation_type", ""),
        network_policy=getattr(spec, "network_policy", ""),
        command_template=getattr(spec, "cmd_template", "") or "",
        tool_id=getattr(spec, "name", ""),
    )


def validate_tool_specs(specs: Iterable[object]) -> list[ResearchGuardDecision]:
    return [validate_tool_spec(spec) for spec in specs]

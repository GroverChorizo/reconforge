"""Contextual research guard (defensive C2 research).

ReconForge is a research framework, not an exploitation framework — the
:mod:`tools.registry` already gates every tool through
``opsec.assert_execution_allowed`` on recon/resource-dev tactics. This module
adds a *behaviour*-level fence for the proxyless-C2 research workflow.

The distinction that matters
----------------------------
Cataloguing, tagging, and writing detection notes *about* C2 — including
families literally named "RAT", "implant", "beacon", or "botnet" — is allowed.
*Executing* C2 behaviour is not. So the guard keys off the declared
``operation_type`` / ``network_policy`` and the actual ``cmd_template`` an
operation would run, **never** off whether scary words appear in a description.

  "document this C2 family"          -> allowed   (taxonomy_only)
  "analyze this PCAP for beaconing"  -> allowed   (local_telemetry_analysis)
  "extract IOCs from this README"    -> allowed   (local_static_analysis)
  "run this C2 server"               -> BLOCKED
  "build an implant" / "gen payload" -> BLOCKED
  "open a listener" / reverse shell  -> BLOCKED

The guard is intentionally fail-closed: a tool with no declared safety
metadata is blocked, and an unknown operation type is treated as unsafe.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# ── vocabularies ──────────────────────────────────────────────────
# Operation types, ordered loosely from safest to unsafe.
OPERATION_TYPES = frozenset({
    "taxonomy_only",            # metadata/labels only, no artifact touched
    "local_static_analysis",   # read a local file (README/source/IOC text)
    "local_telemetry_analysis",# parse a local PCAP/Zeek/Suricata/log artifact
    "passive_intel_lookup",    # read-only public intel (no target traffic)
    "scoped_live_probe",       # touches a live target — needs scope+approval
    "blocked_execution",       # explicitly unsafe; always blocked
})

NETWORK_POLICIES = frozenset({
    "none",                 # no network at all (local files only)
    "passive_intel_only",   # read-only third-party intel sources
    "local_lab_only",       # traffic confined to the operator's lab
    "scoped_target_only",   # only toward an in-scope, approved target
    "blocked",              # no network permitted; always blocked
})

# Operation types that may NOT reach a live/scoped target.
_LOCAL_OR_PASSIVE_OPS = frozenset({
    "taxonomy_only", "local_static_analysis",
    "local_telemetry_analysis", "passive_intel_lookup",
})


# ── unsafe command-template signatures ────────────────────────────
# These match the *command a tool would run*, not prose. Each pattern keys a
# block reason. Word boundaries keep "msfconsole" from matching inside a
# markdown sentence — the guard is only ever handed real cmd templates.
_UNSAFE_CMD_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("opens_listener", re.compile(
        r"\b(nc|ncat|netcat)\b.*\s-\w*l\w*\b|\bsocat\b.*\blisten\b|"
        r"\blisten(er)?\b\s*(start|--start|on)|\bbind\s+shell\b", re.I)),
    ("starts_c2_server", re.compile(
        r"\b(teamserver|c2[-_ ]*server|covenant|mythic|sliver[-_ ]?(daemon|server)|"
        r"empire[-_ ]server|merlin(server)?|trevorc2|silenttrinity|havoc)\b|"
        r"\bstart[-_ ]?(listener|c2|teamserver)\b", re.I)),
    ("generates_payload", re.compile(
        r"\bmsfvenom\b|\b-p\s+\w+/(meterpreter|shell)\b|\bgenerate[-_ ]?(payload|implant|stager|beacon)\b|"
        r"\bveil\b|\bshellter\b|\bunicorn(\.py)?\b|\bdonut\b", re.I)),
    ("generates_shellcode", re.compile(
        r"\bshellcode\b.*\b(generate|gen|build|--out|-o)\b|\bmsfvenom\b.*\b-f\s+(c|raw|py|dll|exe)\b",
        re.I)),
    ("creates_persistence", re.compile(
        r"\b(schtasks|sc\s+create|crontab|New-Service|reg\s+add)\b.*\b(payload|implant|beacon|backdoor)\b|"
        r"\bpersist(ence)?\b\s*(--install|install|add)", re.I)),
    ("reverse_shell", re.compile(
        r"\breverse[-_ ]?shell\b|/dev/tcp/|\bbash\s+-i\b.*>&|\bpython.*socket.*subprocess\b", re.I)),
    # credential_theft is checked before postex_module so a specific creds
    # verb (sekurlsa::logonpasswords) is labelled as theft, not the generic
    # framework name it rides on.
    ("credential_theft", re.compile(
        r"sekurlsa::logonpasswords|lsadump::|\b(hashdump|creds_all|"
        r"dump[-_ ]?(creds|lsass|sam|ntds))\b", re.I)),
    ("postex_module", re.compile(
        r"\b(meterpreter|mimikatz|sekurlsa|lsadump|kerberoast|secretsdump|"
        r"responder\b.*-I|invoke-mimikatz|rubeus)\b", re.I)),
    ("public_callback_infra", re.compile(
        r"\b(ngrok|--public|0\.0\.0\.0:\d+.*\b(c2|beacon|implant)\b)|"
        r"\bexpose\b.*\b(listener|c2|callback)\b", re.I)),
)


# ── result type ───────────────────────────────────────────────────
@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str                      # machine-readable reason key
    detail: str = ""                 # human-readable explanation

    def __bool__(self) -> bool:      # `if guard_check(...):`
        return self.allowed


@dataclass(frozen=True)
class OperationContext:
    """Everything the guard needs to rule on one operation.

    ``command_template`` is the actual command a tool would execute (may be
    empty for taxonomy/metadata ops). ``description`` is free prose and is
    *never* used to block — it exists only for logging.
    """
    workflow_id: str
    tool_id: str
    operation_type: str
    network_policy: str
    command_template: str = ""
    input_artifact_type: str = ""    # "pcap" | "zeek" | "readme" | "metadata" | ...
    has_safety_metadata: bool = True
    scope_ok: bool = False           # ScopeGuard verdict for live ops
    description: str = ""


def _ok(reason: str, detail: str = "") -> GuardDecision:
    return GuardDecision(True, reason, detail)


def _block(reason: str, detail: str = "") -> GuardDecision:
    return GuardDecision(False, reason, detail)


def scan_command_template(cmd: str) -> Optional[tuple[str, str]]:
    """Return ``(reason_key, matched_text)`` if *cmd* looks like unsafe
    execution, else ``None``. Operates only on a real command string.
    """
    if not cmd:
        return None
    for reason, pat in _UNSAFE_CMD_PATTERNS:
        m = pat.search(cmd)
        if m:
            return reason, m.group(0)
    return None


def evaluate(ctx: OperationContext) -> GuardDecision:
    """Rule on a single operation. Fail-closed.

    Order: structural hard-blocks first (operation_type / network_policy /
    missing metadata), then command-template signature scan, then the
    live-target scope check. Taxonomy/static/telemetry ops with no command
    sail through regardless of how their description reads.
    """
    # Fail-closed on unknown vocabulary.
    if ctx.operation_type not in OPERATION_TYPES:
        return _block("unknown_operation_type",
                      f"operation_type {ctx.operation_type!r} is not recognised")
    if ctx.network_policy not in NETWORK_POLICIES:
        return _block("unknown_network_policy",
                      f"network_policy {ctx.network_policy!r} is not recognised")

    # A tool that never declared how it behaves is not trusted to run.
    if not ctx.has_safety_metadata:
        return _block("no_safety_metadata",
                      f"tool {ctx.tool_id!r} declares no safety metadata")

    # Explicit unsafe markers.
    if ctx.operation_type == "blocked_execution":
        return _block("blocked_execution", "operation is marked blocked_execution")
    if ctx.network_policy == "blocked":
        return _block("network_blocked", "network_policy is blocked")

    # The behaviour fence: inspect the real command.
    hit = scan_command_template(ctx.command_template)
    if hit is not None:
        reason, matched = hit
        return _block(reason, f"command template matched unsafe pattern: {matched!r}")

    # A local/passive op must not carry a live-target network policy.
    if ctx.operation_type in _LOCAL_OR_PASSIVE_OPS:
        if ctx.network_policy in ("scoped_target_only", "local_lab_only"):
            return _block("policy_mismatch",
                          f"{ctx.operation_type} may not use network_policy "
                          f"{ctx.network_policy!r}")
        return _ok("allowed_local_or_passive",
                   f"{ctx.operation_type} permitted (network: {ctx.network_policy})")

    # The only remaining op that touches a live target.
    if ctx.operation_type == "scoped_live_probe":
        if ctx.network_policy not in ("scoped_target_only", "local_lab_only"):
            return _block("policy_mismatch",
                          "scoped_live_probe requires scoped_target_only or local_lab_only")
        if not ctx.scope_ok:
            return _block("scope_unverified",
                          "scoped_live_probe requires a passing ScopeGuard verdict")
        return _ok("allowed_scoped_live", "scoped live probe within approved scope")

    # Unreachable given the vocabulary check above; fail-closed anyway.
    return _block("unhandled", "no rule matched; blocking by default")


def assert_safe(ctx: OperationContext) -> None:
    """Raise :class:`ResearchGuardError` if *ctx* is not allowed."""
    decision = evaluate(ctx)
    if not decision.allowed:
        raise ResearchGuardError(decision.reason, decision.detail, ctx)


class ResearchGuardError(RuntimeError):
    def __init__(self, reason: str, detail: str, ctx: OperationContext):
        self.reason = reason
        self.detail = detail
        self.ctx = ctx
        super().__init__(f"[research_guard] {reason}: {detail} "
                         f"(tool={ctx.tool_id}, op={ctx.operation_type})")

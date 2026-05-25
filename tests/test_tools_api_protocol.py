"""Phase C Batch 4 — API / protocol tool config.

graphw00f / clairvoyance / inql / swagger_jacker.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


BATCH_4 = ("graphw00f", "clairvoyance", "inql", "swagger_jacker")


@pytest.mark.parametrize("key", BATCH_4)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS


@pytest.mark.parametrize("key", BATCH_4)
def test_tool_default_enabled(key):
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", BATCH_4)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY


@pytest.mark.parametrize("key", BATCH_4)
def test_tool_has_valid_safety_class(key):
    assert R.REGISTRY[key].safety_class in {
        "passive", "low_active", "mod_active", "intrusive", "disabled"
    }


def test_default_tools_and_registry_cmd_match():
    """Where a tool exists in both registries, the cmd_template should
    match the _DEFAULT_TOOLS cmd. (Drift between the two has historically
    caused agents to call something different from what the operator sees
    in Settings.)"""
    for key in BATCH_4:
        dt_cmd = main._DEFAULT_TOOLS[key]["cmd"]
        rg_cmd = R.REGISTRY[key].cmd_template
        assert dt_cmd == rg_cmd, (
            f"{key} drifted: _DEFAULT_TOOLS={dt_cmd!r}, "
            f"REGISTRY.cmd_template={rg_cmd!r}"
        )

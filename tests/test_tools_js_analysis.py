"""Phase C Batch 3 — JS analysis tool config.

jsluice / mantra / TruffleHog. Static-shape only; subprocess execution
is verified end-to-end on the Parrot box.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


BATCH_3 = ("jsluice", "mantra", "trufflehog")


@pytest.mark.parametrize("key", BATCH_3)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS


@pytest.mark.parametrize("key", BATCH_3)
def test_tool_default_enabled(key):
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", BATCH_3)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY


@pytest.mark.parametrize("key", BATCH_3)
def test_tool_has_valid_safety_class(key):
    assert R.REGISTRY[key].safety_class in {
        "passive", "low_active", "mod_active", "intrusive", "disabled"
    }


def test_binary_names_match_install_path():
    # The first token of each cmd template is what `is_tool_available()`
    # calls `shutil.which()` on. Verify they match what the Dockerfile
    # actually installs.
    binaries = {
        "jsluice":    "jsluice",
        "mantra":     "mantra",
        "trufflehog": "trufflehog",
    }
    for key, expected in binaries.items():
        assert main._DEFAULT_TOOLS[key]["cmd"].split()[0] == expected


def test_trufflehog_parse_mode_is_jsonl():
    # TruffleHog --json emits one JSON document per detection on its own
    # line — exactly the jsonl pattern httpx/nuclei use.
    assert main._DEFAULT_TOOLS["trufflehog"]["parse_mode"] == "jsonl"

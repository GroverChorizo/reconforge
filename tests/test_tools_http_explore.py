"""Phase C Batch 2 — HTTP exploration tool config.

Verifies that katana, feroxbuster, x8, and kiterunner are wired into both
registries with correctly-shaped cmd templates and valid safety classes.
Static-shape tests only; no subprocess spawning.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


BATCH_2 = ("katana", "feroxbuster", "x8", "kiterunner")


@pytest.mark.parametrize("key", BATCH_2)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS


@pytest.mark.parametrize("key", BATCH_2)
def test_tool_default_enabled(key):
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", BATCH_2)
def test_tool_has_cmd_template(key):
    cmd = main._DEFAULT_TOOLS[key]["cmd"]
    assert cmd
    # First token must be the binary name (used by is_tool_available()).
    binary = cmd.split()[0]
    assert binary == {
        "katana":      "katana",
        "feroxbuster": "feroxbuster",
        "x8":          "x8",
        "kiterunner":  "kr",     # Kiterunner's binary is `kr`, not `kiterunner`
    }[key]


@pytest.mark.parametrize("key", BATCH_2)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY


@pytest.mark.parametrize("key", BATCH_2)
def test_tool_has_valid_safety_class(key):
    spec = R.REGISTRY[key]
    assert spec.safety_class in {
        "passive", "low_active", "mod_active", "intrusive", "disabled"
    }


# Kiterunner's spec references $WORDLIST_DIR$ — verify the cross-cutting
# placeholder Phase C introduces actually gets resolved.
def test_kiterunner_wordlist_dir_resolves():
    v = main._standard_vars(domain="acme.com", output="/o", target="api.acme.com")
    v["$WORDLIST_DIR$"] = "/usr/share/seclists"
    cmd = main.build_cmd(main._DEFAULT_TOOLS["kiterunner"]["cmd"], v)
    joined = " ".join(cmd)
    assert "$WORDLIST_DIR$" not in joined
    assert "routes-large.kite" in joined
    assert "/usr/share/seclists" in joined

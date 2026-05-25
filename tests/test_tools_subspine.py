"""Phase C Batch 1 — subdomain spine tool config.

Verifies that BBOT, puredns, and cdncheck are wired into both registries
(main.py:_DEFAULT_TOOLS and tools/registry.py:REGISTRY), have correctly-
shaped cmd templates, and that the `$WORDLIST_DIR$`/`$SHODAN_KEY$`/etc
placeholders that Phase C introduces are honored by build_cmd().

These are static-shape tests — they do NOT spawn the binaries. End-to-end
verification on the Parrot box is the operator's job per the plan.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


BATCH_1 = ("bbot", "puredns", "cdncheck")


# ── pipeline-side registry (main.py:_DEFAULT_TOOLS) ───────────────
@pytest.mark.parametrize("key", BATCH_1)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS, f"{key} missing from main._DEFAULT_TOOLS"


@pytest.mark.parametrize("key", BATCH_1)
def test_tool_default_enabled(key):
    # Phase B flipped everything to enabled-by-default; new Batch 1 tools
    # follow the same default. is_tool_available() still suppresses
    # tools whose binaries aren't installed.
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", BATCH_1)
def test_tool_has_cmd_template(key):
    cmd = main._DEFAULT_TOOLS[key]["cmd"]
    assert cmd, f"{key} has empty cmd template"
    # First token is the binary name — used by is_tool_available().
    binary = cmd.split()[0]
    assert binary, f"{key} cmd template has no binary"


# ── agent-side registry (tools/registry.py:REGISTRY) ──────────────
@pytest.mark.parametrize("key", BATCH_1)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY, f"{key} missing from tools.registry.REGISTRY"


@pytest.mark.parametrize("key", BATCH_1)
def test_tool_has_safety_class(key):
    spec = R.REGISTRY[key]
    assert spec.safety_class in {
        "passive", "low_active", "mod_active", "intrusive", "disabled"
    }, f"{key} has invalid safety_class {spec.safety_class!r}"


@pytest.mark.parametrize("key", BATCH_1)
def test_tool_has_handler(key):
    spec = R.REGISTRY[key]
    assert spec.handler in {"enum_stdout", "enum_file", "crtsh", "dnsx",
                            "httpx", "nuclei", "gowitness", "adaptive"}, (
        f"{key} declares unknown handler {spec.handler!r}"
    )


# ── cross-cutting plumbing: _standard_vars + build_cmd ────────────
class TestStandardVars:

    def test_returns_all_new_placeholders(self):
        v = main._standard_vars(domain="acme.com", output="/tmp/x")
        # Phase C added these four cross-cutting tokens.
        assert "$WORDLIST_DIR$"       in v
        assert "$RESOLVERS_FILE$"     in v
        assert "$SHODAN_KEY$"         in v
        assert "$SECURITYTRAILS_KEY$" in v
        assert "$INTERACTSH_URL$"     in v
        # Pre-existing tokens still present (no regression).
        assert v["$DOMAIN$"] == "acme.com"
        assert v["$OUTPUT$"] == "/tmp/x"

    def test_target_falls_back_to_domain(self):
        v = main._standard_vars(domain="acme.com")
        assert v["$TARGET$"]    == "acme.com"
        assert v["$SUBDOMAIN$"] == "acme.com"

    def test_build_cmd_substitutes_new_placeholder(self):
        # A cmd template referencing one of the new tokens should resolve
        # without leaving the placeholder in place.
        v = main._standard_vars(domain="acme.com", output="/o")
        v["$WORDLIST_DIR$"] = "/tmp/seclists"
        cmd = main.build_cmd(
            "ffuf -w $WORDLIST_DIR$/common.txt -u https://$DOMAIN$/FUZZ -o $OUTPUT$",
            v,
        )
        joined = " ".join(cmd)
        assert "$WORDLIST_DIR$" not in joined
        assert "/tmp/seclists" in joined
        assert "acme.com" in joined


# ── BBOT-specific parse mode ──────────────────────────────────────
class TestBBOTParseMode:

    def test_bbot_uses_dir_output(self):
        # BBOT writes a directory tree, not a single .txt file. The
        # _DEFAULT_TOOLS spec declares parse_mode='bbot' so _run_enum_cli
        # knows to recurse the dir for subdomains.txt.
        assert main._DEFAULT_TOOLS["bbot"]["parse_mode"] == "bbot"

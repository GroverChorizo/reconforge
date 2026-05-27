"""Playbook catalog — every tool referenced by docs/RECON_PLAYBOOK.md is
registered in both _DEFAULT_TOOLS and tools/registry.py:REGISTRY with
matching command templates.

Tools added 2026-05-27 from the operator-research document. Static-shape
tests only; subprocess execution is verified end-to-end on the Parrot box.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


PLAYBOOK_CATALOG = (
    # PD stack additions
    "chaos", "shuffledns", "mapcidr", "tlsx", "naabu", "alterx",
    "notify", "interactsh", "uncover",
    # Tomnomnom utility chain
    "gau", "waybackurls", "anew", "unfurl", "qsreplace", "gf", "hakrawler",
    # Specialty attack tools
    "arjun", "dalfox", "crlfuzz", "paramspider", "sqlmap", "masscan",
    "gobuster", "dirsearch", "gxss", "subjs", "sourcemapper",
    "secretfinder", "gotator", "dnsgen",
    # Resolvers + scope helpers
    "dnsvalidator", "hacker_scoper",
)


@pytest.mark.parametrize("key", PLAYBOOK_CATALOG)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS, (
        f"{key} missing from main._DEFAULT_TOOLS — Settings UI won't see it"
    )


@pytest.mark.parametrize("key", PLAYBOOK_CATALOG)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY, (
        f"{key} missing from tools.registry.REGISTRY — agents can't dispatch it"
    )


@pytest.mark.parametrize("key", PLAYBOOK_CATALOG)
def test_tool_default_enabled(key):
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", PLAYBOOK_CATALOG)
def test_tool_cmd_no_drift(key):
    """The single most-likely source of "the agent ran something different
    from what the operator saw in Settings" — guard against it."""
    dt_cmd = main._DEFAULT_TOOLS[key]["cmd"]
    rg_cmd = R.REGISTRY[key].cmd_template
    assert dt_cmd == rg_cmd, (
        f"{key} drifted between registries:\n"
        f"  _DEFAULT_TOOLS:        {dt_cmd!r}\n"
        f"  REGISTRY.cmd_template: {rg_cmd!r}"
    )


@pytest.mark.parametrize("key", PLAYBOOK_CATALOG)
def test_tool_has_valid_safety_class(key):
    assert R.REGISTRY[key].safety_class in {
        "passive", "low_active", "mod_active", "intrusive", "disabled"
    }, f"{key} has invalid safety_class {R.REGISTRY[key].safety_class!r}"


# ── catalog-wide sanity ───────────────────────────────────────────
def test_total_tool_count_at_or_above_playbook_floor():
    """The playbook references ~50 tools across 20 phases. After Phase C
    plus this catalog expansion we should be at or above that floor.
    Lower-bounded so future additions don't break this assertion."""
    assert len(main._DEFAULT_TOOLS) >= 50
    assert len(R.REGISTRY) >= 45  # registry sometimes lacks UI-only utils


def test_critical_pipeline_tools_present():
    """The master pipeline at the bottom of docs/RECON_PLAYBOOK.md
    depends on these being available — gate-check them explicitly."""
    must_have = ("subfinder", "amass", "github_subdomains", "crtsh",
                 "shuffledns", "puredns", "cdncheck", "tlsx", "naabu",
                 "httpx", "gowitness", "katana", "gau", "waybackurls",
                 "jsluice", "trufflehog", "arjun", "ffuf", "gf",
                 "qsreplace", "unfurl", "anew", "dalfox", "crlfuzz",
                 "nuclei", "interactsh", "notify")
    missing = [t for t in must_have if t not in main._DEFAULT_TOOLS]
    assert not missing, f"Master pipeline tools missing: {missing}"


def test_gf_patterns_referenced():
    """gf cmd template should use $TARGET$ as the pattern name (xss/sqli/
    etc.). If someone changes it to a fixed pattern, the per-pattern
    pipelines stop working."""
    assert "$TARGET$" in main._DEFAULT_TOOLS["gf"]["cmd"]

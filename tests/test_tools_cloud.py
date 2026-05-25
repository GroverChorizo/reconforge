"""Phase C Batch 5 — cloud tool config.

CloudFox / s3scanner. CloudFox is new to both registries; s3scanner was
already in tools/registry.py as a Phase 14 adaptive entry but missing
from _DEFAULT_TOOLS.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main
from tools import registry as R


BATCH_5 = ("cloudfox", "s3scanner")


@pytest.mark.parametrize("key", BATCH_5)
def test_tool_in_default_tools(key):
    assert key in main._DEFAULT_TOOLS


@pytest.mark.parametrize("key", BATCH_5)
def test_tool_default_enabled(key):
    assert main._DEFAULT_TOOLS[key]["enabled"] is True


@pytest.mark.parametrize("key", BATCH_5)
def test_tool_in_agent_registry(key):
    assert key in R.REGISTRY


def test_cloudfox_uses_aws_profile_placeholder():
    cmd = main._DEFAULT_TOOLS["cloudfox"]["cmd"]
    assert "$AWS_PROFILE$" in cmd, (
        "CloudFox cmd must reference $AWS_PROFILE$ so operators can "
        "switch profiles per-engagement without editing the template."
    )


def test_standard_vars_includes_aws_profile():
    v = main._standard_vars(domain="acme.com")
    assert "$AWS_PROFILE$" in v
    # Defaults to "default" if no setting present.
    assert v["$AWS_PROFILE$"] in {"default", ""}, (
        "AWS_PROFILE default should be 'default' (or empty if config "
        "explicitly overrides). Got: " + repr(v["$AWS_PROFILE$"])
    )


def test_cloudfox_cmd_resolves_after_build():
    v = main._standard_vars(domain="acme.com", output="/tmp/cf.txt")
    v["$AWS_PROFILE$"] = "engagement-x"
    cmd = main.build_cmd(main._DEFAULT_TOOLS["cloudfox"]["cmd"], v)
    joined = " ".join(cmd)
    assert "$AWS_PROFILE$" not in joined
    assert "engagement-x" in joined
    assert "/tmp/cf.txt" in joined


# ── one more drift check across all 5 batches ─────────────────────
PHASE_C_TOOLS_IN_BOTH = (
    "bbot", "puredns", "cdncheck",
    "katana", "feroxbuster", "x8", "kiterunner",
    "jsluice", "mantra", "trufflehog",
    "graphw00f", "clairvoyance", "inql", "swagger_jacker",
    "cloudfox", "s3scanner",
)


@pytest.mark.parametrize("key", PHASE_C_TOOLS_IN_BOTH)
def test_no_cmd_drift_between_registries(key):
    """Across the entire Phase C tool catalog, _DEFAULT_TOOLS and
    REGISTRY must agree on the command template."""
    assert main._DEFAULT_TOOLS[key]["cmd"] == R.REGISTRY[key].cmd_template, (
        f"{key}: _DEFAULT_TOOLS={main._DEFAULT_TOOLS[key]['cmd']!r} "
        f"vs REGISTRY={R.REGISTRY[key].cmd_template!r}"
    )

"""Phase 11 — tools.detect tests."""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tools import detect


# ═══════════════════════════════════════════════════════════
#  catalog sanity
# ═══════════════════════════════════════════════════════════
class TestCatalog:

    def test_catalog_has_all_legacy_tools(self):
        for t in ("subfinder", "amass", "assetfinder", "findomain",
                  "sublist3r", "dnsx", "httpx", "gowitness", "nuclei",
                  "nikto", "wafw00f", "ffuf"):
            assert t in detect.CATALOG

    def test_catalog_has_adaptive_tools(self):
        for t in ("graphw00f", "clairvoyance", "inql", "s3scanner"):
            assert t in detect.CATALOG

    def test_every_entry_has_binary(self):
        for key, entry in detect.CATALOG.items():
            assert entry.binary, f"{key}: missing binary"

    def test_install_method_inferred(self):
        sf = detect.CATALOG["subfinder"]
        assert sf.install_method() == "go"
        assert sf.install_cmd()[0] == "go"


# ═══════════════════════════════════════════════════════════
#  scan
# ═══════════════════════════════════════════════════════════
class TestScan:

    def test_returns_one_per_catalog(self):
        out = detect.scan()
        assert len(out) == len(detect.CATALOG)

    def test_finds_existing_binary(self):
        # Use a tiny catalog with a binary that exists everywhere.
        # `python` is portable enough across CI.
        mini = {"python": detect.ToolEntry("Python", "python")}
        out = detect.scan(mini)
        # Just assert that whichever binary we get, the row roundtrips.
        with patch("shutil.which", return_value="/usr/bin/fake-python"):
            out = detect.scan(mini)
        assert out[0].installed is True
        assert out[0].path == "/usr/bin/fake-python"

    def test_missing_binary(self):
        mini = {"qx": detect.ToolEntry("QX", "qx-does-not-exist-anywhere",
                                        apt="qx")}
        out = detect.scan(mini)
        assert out[0].installed is False
        assert out[0].install_cmd == ["sudo", "apt-get", "install", "-y", "qx"]


# ═══════════════════════════════════════════════════════════
#  install_plan
# ═══════════════════════════════════════════════════════════
class TestInstallPlan:

    def test_apt_commands_coalesced(self):
        # Two missing apt tools should become one apt-get install -y A B.
        mini = {
            "a": detect.ToolEntry("A", "a-doesnt-exist", apt="aa"),
            "b": detect.ToolEntry("B", "b-doesnt-exist", apt="bb"),
        }
        plan = detect.install_plan(mini)
        assert len(plan) == 1
        assert plan[0][:4] == ["sudo", "apt-get", "install", "-y"]
        assert set(plan[0][4:]) == {"aa", "bb"}

    def test_go_install_kept_separate(self):
        mini = {
            "g1": detect.ToolEntry("G1", "g1-x",
                                    go_install="github.com/x/y@latest"),
            "g2": detect.ToolEntry("G2", "g2-x",
                                    go_install="github.com/a/b@latest"),
        }
        plan = detect.install_plan(mini)
        assert len(plan) == 2
        assert all(p[0] == "go" for p in plan)

    def test_mixed_backends(self):
        mini = {
            "a": detect.ToolEntry("A", "ax", apt="aa"),
            "g": detect.ToolEntry("G", "gx",
                                   go_install="github.com/x/y@latest"),
            "p": detect.ToolEntry("P", "px", pip="px-pkg"),
        }
        plan = detect.install_plan(mini)
        assert len(plan) == 3
        backends = {tuple(c[:1]) for c in plan}
        assert ("sudo",) in backends
        assert ("go",)   in backends
        assert ("pip",)  in backends

    def test_install_plan_human_rendering(self):
        rendered = detect.install_plan_human({})
        assert "already installed" in rendered

    def test_missing_only_filter(self):
        # If all installed, plan is empty.
        with patch("shutil.which", return_value="/usr/bin/x"):
            plan = detect.install_plan()
        assert plan == []


# ═══════════════════════════════════════════════════════════
#  summarize
# ═══════════════════════════════════════════════════════════
class TestSummarize:

    def test_buckets(self):
        with patch("shutil.which", return_value="/usr/bin/x"):
            s = detect.summarize()
        assert s["installed"] == s["total"]
        assert s["missing"] == 0
        with patch("shutil.which", return_value=None):
            s = detect.summarize()
        assert s["missing"] == s["total"]

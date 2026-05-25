"""
Tests for Phase 3 — ATT&CK taxonomy, mapper, heatmap, and OPSEC boundary.

The mapper must:
  - return canonical techniques per vuln_class (rule table)
  - boost confidence on keyword hits
  - persist to attack_techniques table idempotently
  - cap confidence at 0.95
  - tolerate unknown vuln_class
The heatmap must always return all 14 tactics (zero-fill missing).
The OPSEC boundary must allow TA0043/TA0042 and refuse the rest.
"""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from attack import taxonomy, mapper, heatmap
from core import opsec
from db.migrations import runner as MIG


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def migrated_db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    MIG.run_pending(conn)
    yield conn
    conn.close()


def _insert_finding(conn, bug_id="BUG-T-001", job_id="J1", domain="x.com",
                    vuln_class="ssrf", title="t", description=""):
    conn.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, description) "
        "VALUES (?,?,?,?,?,?)",
        (bug_id, job_id, domain, vuln_class, title, description)
    )
    conn.commit()
    return conn.execute(
        "SELECT id FROM findings WHERE bug_id=?", (bug_id,)
    ).fetchone()[0]


# ═══════════════════════════════════════════════════════════
#  TAXONOMY
# ═══════════════════════════════════════════════════════════
class TestTaxonomy:

    def test_loads_14_tactics(self):
        ts = taxonomy.tactics()
        assert len(ts) == 14
        ids = [t["id"] for t in ts]
        assert ids[0] == "TA0043"  # Reconnaissance first
        assert ids[-1] == "TA0040"  # Impact last

    def test_recon_and_resource_dev_present(self):
        assert taxonomy.get_tactic("TA0043")["name"] == "Reconnaissance"
        assert taxonomy.get_tactic("TA0042")["name"] == "Resource Development"

    def test_technique_lookup(self):
        t = taxonomy.get_technique("T1190")
        assert t is not None
        assert "TA0001" in t["tactics"]

    def test_sub_technique_lookup(self):
        t = taxonomy.get_technique("T1552.005")
        assert t is not None
        assert "TA0006" in t["tactics"]

    def test_split_sub(self):
        assert taxonomy.split_sub("T1190") == ("T1190", None)
        assert taxonomy.split_sub("T1552.005") == ("T1552", "T1552.005")

    def test_techniques_for_tactic(self):
        recon_techs = taxonomy.techniques_for_tactic("TA0043")
        assert len(recon_techs) >= 5  # we ship at least T1589-T1596


# ═══════════════════════════════════════════════════════════
#  MAPPER — RULE TABLE PER VULN CLASS
# ═══════════════════════════════════════════════════════════
class TestMapperRules:

    @pytest.mark.parametrize("vuln_class,expected_tech", [
        ("ssrf",          "T1190"),
        ("idor",          "T1190"),
        ("graphql",       "T1190"),
        ("xss",           "T1190"),
        ("jwt",           "T1552"),
        ("takeover",      "T1583.001"),
        ("api_misconfig", "T1190"),
        ("bizlogic",      "T1565"),
        ("open_redirect", "T1566"),
        ("cors",          "T1213"),
    ])
    def test_canonical_technique_present(self, vuln_class, expected_tech):
        hits = mapper.map_finding({"vuln_class": vuln_class, "title": "t"})
        assert any(h.technique_id == expected_tech.split(".")[0] for h in hits), \
            f"{vuln_class} should map to {expected_tech}"

    def test_ssrf_maps_cloud_metadata(self):
        hits = mapper.map_finding({"vuln_class": "ssrf", "title": "t"})
        assert any(h.technique_id == "T1552" and h.sub_technique_id == "T1552.005"
                   for h in hits)

    def test_takeover_high_confidence(self):
        hits = mapper.map_finding({"vuln_class": "takeover", "title": "t"})
        top = hits[0]
        assert top.technique_id == "T1583"
        assert top.sub_technique_id == "T1583.001"
        assert top.confidence >= 0.95 - 0.001

    def test_unknown_vuln_class_returns_empty(self):
        hits = mapper.map_finding({"vuln_class": "totally_unknown", "title": "t"})
        assert hits == []

    def test_sorted_by_confidence_desc(self):
        hits = mapper.map_finding({"vuln_class": "ssrf", "title": "t"})
        confs = [h.confidence for h in hits]
        assert confs == sorted(confs, reverse=True)


# ═══════════════════════════════════════════════════════════
#  MAPPER — KEYWORD BOOSTING
# ═══════════════════════════════════════════════════════════
class TestMapperKeywords:

    def test_imds_keyword_boosts_cloud_metadata(self):
        base = mapper.map_finding({"vuln_class": "ssrf", "title": "ssrf"})
        with_kw = mapper.map_finding({
            "vuln_class": "ssrf",
            "title": "ssrf",
            "description": "fetches 169.254.169.254 imds"
        })
        b = [h for h in base if h.sub_technique_id == "T1552.005"][0]
        w = [h for h in with_kw if h.sub_technique_id == "T1552.005"][0]
        assert w.confidence > b.confidence

    def test_keyword_adds_new_technique(self):
        # 'webshell' is a keyword for T1505.003 — not in any rule table.
        hits = mapper.map_finding({
            "vuln_class": "other",   # unknown class so rules contribute nothing
            "title": "uploaded webshell",
        })
        assert any(h.technique_id == "T1505" for h in hits)

    def test_confidence_capped_at_095(self):
        # smash multiple keyword matches against a high-base rule
        hits = mapper.map_finding({
            "vuln_class": "takeover",
            "title": "dangling cname subdomain takeover via github.io",
            "description": "azurewebsites s3.amazonaws.com nxdomain",
        })
        top = hits[0]
        assert top.confidence <= 0.95 + 0.0001


# ═══════════════════════════════════════════════════════════
#  MAPPER — PERSISTENCE
# ═══════════════════════════════════════════════════════════
class TestPersistence:

    def test_persist_writes_rows(self, migrated_db):
        fid = _insert_finding(migrated_db, vuln_class="ssrf",
                              description="fetches 169.254.169.254")
        hits = mapper.persist_for_finding(migrated_db, fid,
                                          {"vuln_class": "ssrf",
                                           "title": "x",
                                           "description": "fetches 169.254.169.254"})
        migrated_db.commit()
        rows = migrated_db.execute(
            "SELECT technique_id, sub_technique_id, confidence FROM attack_techniques "
            "WHERE finding_id=?", (fid,)
        ).fetchall()
        assert len(rows) == len(hits)
        techs = {r["technique_id"] for r in rows}
        assert "T1190" in techs
        assert "T1552" in techs

    def test_persist_is_idempotent(self, migrated_db):
        fid = _insert_finding(migrated_db, vuln_class="jwt")
        mapper.persist_for_finding(migrated_db, fid, {"vuln_class": "jwt", "title": "t"})
        mapper.persist_for_finding(migrated_db, fid, {"vuln_class": "jwt", "title": "t"})
        migrated_db.commit()
        rows = migrated_db.execute(
            "SELECT COUNT(*) FROM attack_techniques WHERE finding_id=?", (fid,)
        ).fetchone()
        # second call deletes the first batch then re-inserts → exactly one mapping set
        assert rows[0] == len(mapper.map_finding({"vuln_class": "jwt", "title": "t"}))


# ═══════════════════════════════════════════════════════════
#  HEATMAP
# ═══════════════════════════════════════════════════════════
class TestHeatmap:

    def test_empty_job_returns_all_14_tactics(self, migrated_db):
        h = heatmap.aggregate(migrated_db, "no-such-job")
        assert len(h) == 14
        assert all(v["count"] == 0 for v in h.values())

    def test_aggregates_across_findings(self, migrated_db):
        # two findings, both SSRF → expect TA0001 (T1190) populated
        f1 = _insert_finding(migrated_db, bug_id="BUG-H-001", vuln_class="ssrf")
        f2 = _insert_finding(migrated_db, bug_id="BUG-H-002", vuln_class="ssrf")
        mapper.persist_for_finding(migrated_db, f1, {"vuln_class": "ssrf", "title": "a"})
        mapper.persist_for_finding(migrated_db, f2, {"vuln_class": "ssrf", "title": "b"})
        migrated_db.commit()
        h = heatmap.aggregate(migrated_db, "J1")
        assert h["TA0001"]["count"] >= 2  # both SSRFs hit T1190 under Initial Access
        assert h["TA0001"]["max_confidence"] >= 0.9
        top = h["TA0001"]["top_techniques"][0]
        assert top["id"] == "T1190"

    def test_top_techniques_capped(self, migrated_db):
        f = _insert_finding(migrated_db, bug_id="BUG-H-003", vuln_class="ssrf",
                            description="imds 169.254.169.254")
        mapper.persist_for_finding(migrated_db, f, {
            "vuln_class": "ssrf", "title": "x",
            "description": "imds 169.254.169.254"
        })
        migrated_db.commit()
        h = heatmap.aggregate(migrated_db, "J1", top_n=2)
        for tactic_data in h.values():
            assert len(tactic_data["top_techniques"]) <= 2


# ═══════════════════════════════════════════════════════════
#  OPSEC BOUNDARY
# ═══════════════════════════════════════════════════════════
class TestOpsecBoundary:

    def test_recon_technique_allowed(self):
        # T1595 (Active Scanning) → TA0043 Reconnaissance
        assert opsec.is_execution_allowed("T1595") is True

    def test_resource_dev_allowed(self):
        # T1583.001 (Acquire Domains) → TA0042
        assert opsec.is_execution_allowed("T1583.001") is True

    def test_initial_access_blocked(self):
        # T1190 → TA0001 Initial Access
        assert opsec.is_execution_allowed("T1190") is False

    def test_credential_access_blocked(self):
        assert opsec.is_execution_allowed("T1552") is False

    def test_impact_blocked(self):
        assert opsec.is_execution_allowed("T1485") is False  # Data Destruction

    def test_assert_no_longer_raises_on_blocked(self):
        # Phase B: assert_execution_allowed is now a no-op. The
        # is_execution_allowed query stays for UI-badging ("this is
        # exploitation, not recon"), but tool execution is no longer
        # fenced to TA0043/TA0042 — agents pick by job context.
        opsec.assert_execution_allowed("T1190", context="unit test")

    def test_assert_passes_on_allowed(self):
        opsec.assert_execution_allowed("T1595")  # no raise

    def test_filter_executable_now_passthrough(self):
        # Phase B: filter_executable returns input unchanged (no longer
        # drops non-recon techniques). is_execution_allowed still answers
        # the classification question for UI use.
        techs = ["T1595", "T1190", "T1583.001", "T1552"]
        assert opsec.filter_executable(techs) == techs

    def test_unknown_technique_not_blocked(self):
        # unknown ID returns True so missing taxonomy data doesn't paralyze
        # the runtime; mapper should warn separately.
        assert opsec.is_execution_allowed("T9999") is True


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════
class TestCLI:

    def test_sample_cli_returns_json(self):
        r = subprocess.run(
            [sys.executable, "-m", "attack.mapper", "sample"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert isinstance(data, list)
        assert len(data) == 10  # _SAMPLE_FINDINGS
        for entry in data:
            assert "finding" in entry and "hits" in entry

    def test_map_cli_single_finding(self):
        r = subprocess.run(
            [sys.executable, "-m", "attack.mapper", "map",
             "--vuln-class", "takeover", "--title", "subdomain takeover"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, r.stderr
        hits = json.loads(r.stdout)
        assert any(h["technique_id"] == "T1583" for h in hits)

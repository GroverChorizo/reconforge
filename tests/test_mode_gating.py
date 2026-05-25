"""Phase 15 — Pipeline gating by operator mode + workflow primitive + preflight.

Covers:
  * tools.registry safety_class on every spec; MODE_ALLOWLISTS shape;
    tools_for_mode / is_tool_allowed_in_mode lookups; safety_class_of
    falls back to 'disabled' for unknown tools.
  * core.opsec ModeViolation; assert_tool_allowed gates correctly per mode;
    preflight() returns the expected envelope including rate-limit
    minimum logic; render_command_preview substitutes $DOMAIN$/$TARGET$.
  * core.workflows baseline registry covers all 7 operator modes; each
    workflow's tool list is mode-consistent.
  * tools.registry.dispatch refuses with a "mode gate refused" ToolResult
    when called with a passive mode against an active-class tool.
  * agents.hunter.select_playbooks filters by mode (passive_recon → []).
  * core.pipeline.run_agentic_pipeline sets ctx.inputs["mode"].
  * api.routes.jobs_preflight returns correct shape for allowed +
    out-of-scope + mode-blocked cases.
  * api.server.dispatch routes the three new endpoints.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import opsec, programs as P, workflows as W
from tools import registry as R
from api import routes, server
from db.migrations import runner as MIG


# ── fixtures ──────────────────────────────────────────────────────
@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    MIG.run_pending(conn)
    yield conn
    conn.close()


@pytest.fixture
def acme(db):
    return P.create_program(
        db,
        name="ACME Program",
        platform="intigriti",
        platform_handle="grover",
        scope=[{
            "type": "wildcard", "value": "*.acme.com", "tier": 2,
            "allowed_methods": ["GET", "POST"],
            "disallowed_methods": ["DELETE"],
            "rate_limit_rps_hint": 5,
            "notes": "API is fragile, throttle.",
        }],
        out_of_scope=[{"type": "domain", "value": "careers.acme.com"}],
        notes="Researcher must respect rate limits. No DoS testing.",
    )


# ── registry: safety_class + mode allowlists ─────────────────────
class TestRegistrySafetyClass:

    def test_every_tool_has_safety_class(self):
        for name, spec in R.REGISTRY.items():
            assert spec.safety_class in {
                "passive", "low_active", "mod_active", "intrusive", "disabled"
            }, f"{name} has unexpected safety_class {spec.safety_class!r}"

    def test_passive_examples(self):
        for name in ("subfinder", "assetfinder", "crtsh", "dnsx", "amass"):
            assert R.safety_class_of(name) == "passive"

    def test_low_active_examples(self):
        for name in ("httpx", "gowitness", "wafw00f"):
            assert R.safety_class_of(name) == "low_active"

    def test_mod_active_examples(self):
        for name in ("nuclei", "graphw00f", "clairvoyance", "inql"):
            assert R.safety_class_of(name) == "mod_active"

    def test_unknown_tool_falls_back_to_disabled(self):
        assert R.safety_class_of("notarealtool") == "disabled"


class TestModeAllowlists:

    def test_all_seven_modes_have_allowlist(self):
        assert set(R.MODE_ALLOWLISTS.keys()) == set(R.OPERATOR_MODES)

    def test_passive_recon_is_strictest(self):
        assert R.MODE_ALLOWLISTS["passive_recon"] == frozenset({"passive"})

    def test_evidence_collection_is_broadest(self):
        assert R.MODE_ALLOWLISTS["evidence_collection"] >= frozenset(
            {"passive", "low_active", "mod_active", "intrusive"}
        )

    def test_report_drafting_passive_only(self):
        assert R.MODE_ALLOWLISTS["report_drafting"] == frozenset({"passive"})

    def test_tools_for_mode_passive(self):
        tools = R.tools_for_mode("passive_recon")
        for t in tools:
            assert R.safety_class_of(t) == "passive"
        assert "subfinder" in tools
        assert "httpx" not in tools
        assert "nuclei" not in tools

    def test_tools_for_mode_active(self):
        tools = R.tools_for_mode("active_recon")
        assert "httpx" in tools
        assert "nuclei" not in tools   # mod_active not allowed

    def test_tools_for_mode_unknown(self):
        assert R.tools_for_mode("ghost") == []

    def test_is_tool_allowed_in_mode(self):
        assert R.is_tool_allowed_in_mode("subfinder", "passive_recon") is True
        assert R.is_tool_allowed_in_mode("nuclei", "passive_recon") is False
        assert R.is_tool_allowed_in_mode("nuclei", "vuln_triage") is True


# ── opsec gate (post-Phase-B: now advisory only, never refuses) ───
class TestOpsecModeGate:

    def test_passive_no_longer_rejects_active_tool(self):
        # Phase B removed mode refusal — the assert is now a no-op.
        opsec.assert_tool_allowed("nuclei", "passive_recon")

    def test_passive_allows_passive_tool(self):
        opsec.assert_tool_allowed("subfinder", "passive_recon")

    def test_active_allows_low_active(self):
        opsec.assert_tool_allowed("httpx", "active_recon")

    def test_unknown_tool_no_longer_blocked(self):
        # Unknown tool used to raise; now it returns (refusal happens
        # later in dispatch on "unknown tool", not at the mode gate).
        opsec.assert_tool_allowed("notatool", "evidence_collection")


class TestOpsecPreflight:

    def test_passive_tool_passive_mode_ok(self):
        out = opsec.preflight("subfinder", "passive_recon")
        assert out["allowed"] is True
        assert out["safety_class"] == "passive"
        assert out["mode"] == "passive_recon"

    def test_active_tool_passive_mode_allowed_with_advisory(self):
        # Phase B: mode no longer blocks. Preflight still surfaces the
        # classification mismatch in the reason field so the modal can
        # warn the operator, but allowed stays True.
        out = opsec.preflight("nuclei", "passive_recon")
        assert out["allowed"] is True
        assert "advisory" in out["reason"]
        assert out["safety_class"] == "mod_active"

    def test_rate_limit_takes_min_of_hint_and_default(self):
        # hint=3, mode=active_recon default=10 → effective 3
        out = opsec.preflight("httpx", "active_recon", rate_limit_hint=3)
        assert out["rate_limit_rps"] == 3

    def test_rate_limit_uses_default_when_no_hint(self):
        out = opsec.preflight("httpx", "active_recon")
        assert out["rate_limit_rps"] == 10

    def test_render_command_preview_substitutes_domain(self):
        argv = opsec.render_command_preview("subfinder", target="acme.com")
        assert "acme.com" in argv
        assert "$DOMAIN$" not in " ".join(argv)

    def test_render_command_preview_substitutes_target(self):
        argv = opsec.render_command_preview("graphw00f", target="https://api.acme.com/graphql")
        assert "https://api.acme.com/graphql" in argv

    def test_render_command_preview_unknown_tool(self):
        assert opsec.render_command_preview("nope") == []


# ── workflows ─────────────────────────────────────────────────────
class TestWorkflows:

    def test_one_workflow_per_mode(self):
        ids = {w.id for w in W.list_workflows()}
        modes = set(R.OPERATOR_MODES)
        # Phase 15 ships one baseline workflow named after each mode.
        assert ids == modes

    def test_get_workflow_lookup(self):
        w = W.get_workflow("passive_recon")
        assert w is not None
        assert w.mode == "passive_recon"
        assert w.safety.traffic_level == "none"

    def test_get_workflow_missing(self):
        assert W.get_workflow("ghost") is None

    def test_workflows_for_mode(self):
        out = W.workflows_for_mode("vuln_triage")
        assert len(out) == 1
        assert out[0].id == "vuln_triage"

    def test_baseline_workflows_are_mode_consistent(self):
        # Every tool declared by a baseline workflow must be allowed in
        # that workflow's own mode. This guards against drift between
        # registry mode allowlists + workflow tool selections.
        for w in W.list_workflows():
            bad = W.validate_workflow_against_mode(w.id)
            assert bad == [], (
                f"workflow {w.id!r} declares tools not allowed in its mode: {bad}"
            )

    def test_workflow_to_dict_roundtrips(self):
        w = W.get_workflow("active_recon")
        d = w.to_dict()
        assert d["id"] == "active_recon"
        assert d["safety"]["default_rate_limit_rps"] == 10
        assert {t["id"] for t in d["tools"]} >= {"httpx", "gowitness"}


# ── dispatch no longer refuses on mode (post-Phase-B) ─────────────
class TestDispatchModeGate:

    def test_dispatch_no_longer_refuses_active_tool_in_passive_mode(self, tmp_path):
        # Phase B removed the mode refusal in dispatch. The call should
        # now proceed to the tool handler (which may then fail for other
        # reasons — missing binary, etc — but NOT with "mode gate refused").
        ctx = R.DispatchContext(
            job_id="J1", domain="acme.com",
            workdir=str(tmp_path), mode="passive_recon",
        )
        result = R.dispatch("nuclei", {"domain": "acme.com"}, ctx)
        # We only assert the refusal *isn't* the mode gate. Real execution
        # may fail because nuclei isn't installed in the test env or the
        # handler raises — both are valid outcomes for this assertion.
        assert result.summary != "mode gate refused"

    def test_dispatch_still_refuses_unknown_tool(self, tmp_path):
        ctx = R.DispatchContext(
            job_id="J1", domain="acme.com",
            workdir=str(tmp_path), mode="passive_recon",
        )
        result = R.dispatch("notatool", {"domain": "acme.com"}, ctx)
        assert result.ok is False
        assert "unknown tool" in result.summary


# ── hunter playbook selection (mode no longer filters) ────────────
class TestHunterPlaybookFilter:

    def test_passive_recon_still_picks_by_signals(self):
        # Phase B: mode no longer filters playbooks. With graphql signal
        # and live_hosts, the full triggered set runs regardless of mode.
        from agents.hunter import select_playbooks
        recon = {"live_hosts": 10, "signals": {"graphql_endpoints": ["/graphql"]}}
        out = select_playbooks(recon, mode="passive_recon")
        assert "graphql" in out
        assert "takeover" in out

    def test_active_recon_picks_by_signals_too(self):
        from agents.hunter import select_playbooks
        recon = {"live_hosts": 10, "signals": {"graphql_endpoints": ["/graphql"],
                                                 "login_pages": ["/login"]}}
        out = select_playbooks(recon, mode="active_recon")
        # With both signals plus live_hosts > 0, the full set fires.
        assert set(out) == {"graphql", "jwt", "idor", "ssrf", "xss",
                             "bizlogic", "api_misconfig", "takeover"}

    def test_vuln_triage_runs_full_set(self):
        from agents.hunter import select_playbooks
        recon = {"live_hosts": 10,
                 "signals": {"graphql_endpoints": ["/g"], "login_pages": ["/l"]}}
        out = select_playbooks(recon, mode="vuln_triage")
        assert set(out) == {"graphql", "jwt", "idor", "ssrf", "xss",
                             "bizlogic", "api_misconfig", "takeover"}


# ── pipeline threads mode through inputs ──────────────────────────
class TestPipelineModeKwarg:

    def test_mode_set_in_inputs(self, db):
        from agents.base import AgentContext
        from core.pipeline import run_agentic_pipeline
        # Stub agents so the pipeline returns immediately. ScopeGuard
        # success path doesn't short-circuit; downstream agents skip
        # cleanly when stubs return success.
        from agents.base import AgentResult

        class _Stub:
            name = "stub"
            def __init__(self, db=None, emit_fn=None): pass
            def run(self, ctx):
                # Capture the mode the orchestrator set on ctx.
                self.observed_mode = (ctx.inputs or {}).get("mode")
                return AgentResult(agent="stub", success=True, output=None)

        class _SG(_Stub): name = "scope_guard"
        class _ST(_Stub): name = "strategist"
        class _RC(_Stub): name = "recon"
        class _HU(_Stub): name = "hunter"
        class _AN(_Stub): name = "analyst"
        class _RP(_Stub): name = "reporter"

        ctx = AgentContext(job_id="J1", program={"in_scope": [{"type": "domain", "value": "acme.com"}]},
                           inputs={"domain": "acme.com"}, db=db)
        result = run_agentic_pipeline(ctx, mode="vuln_triage", agents={
            "scope_guard": _SG, "strategist": _ST, "recon": _RC,
            "hunter": _HU, "analyst": _AN, "reporter": _RP,
        })
        assert ctx.inputs["mode"] == "vuln_triage"
        assert result.status == "completed"

    def test_default_mode_is_passive(self, db):
        from agents.base import AgentContext, AgentResult

        class _Stub:
            name = "stub"
            def __init__(self, db=None, emit_fn=None): pass
            def run(self, ctx):
                return AgentResult(agent="stub", success=True, output=None)

        class _SG(_Stub): name = "scope_guard"
        class _ST(_Stub): name = "strategist"
        class _RC(_Stub): name = "recon"
        class _HU(_Stub): name = "hunter"
        class _AN(_Stub): name = "analyst"
        class _RP(_Stub): name = "reporter"

        from core.pipeline import run_agentic_pipeline
        ctx = AgentContext(job_id="J2", program={"in_scope": [{"type": "domain", "value": "acme.com"}]},
                           inputs={"domain": "acme.com"}, db=db)
        run_agentic_pipeline(ctx, agents={
            "scope_guard": _SG, "strategist": _ST, "recon": _RC,
            "hunter": _HU, "analyst": _AN, "reporter": _RP,
        })
        assert ctx.inputs["mode"] == "passive_recon"


# ── routes ────────────────────────────────────────────────────────
class TestPreflightRoute:

    def test_in_scope_passive_tool_allowed(self, acme, db):
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "api.acme.com",
            "mode": "passive_recon", "tool": "subfinder",
        })
        assert out["allowed"] is True
        assert out["safety_class"] == "passive"
        assert out["allowed_methods"] == ["GET", "POST"]
        assert out["disallowed_methods"] == ["DELETE"]
        assert "fragile" in out["scope_rule_notes"]
        assert out["rate_limit_rps"] == 0   # passive mode default

    def test_out_of_scope_blocked(self, acme, db):
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "careers.acme.com",
            "mode": "passive_recon", "tool": "subfinder",
        })
        assert out["allowed"] is False
        assert "out_of_scope" in out["reason"]

    def test_mode_no_longer_blocks_active_tool_in_passive(self, acme, db):
        # Phase B removed the mode refusal. Preflight returns allowed=True
        # for in-scope targets regardless of safety_class vs mode, and
        # the reason field carries the advisory text instead.
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "api.acme.com",
            "mode": "passive_recon", "tool": "nuclei",
        })
        assert out["allowed"] is True
        assert "advisory" in out["reason"]
        assert out["scope"]["matched"]["value"] == "*.acme.com"

    def test_command_preview_substitutes_target(self, acme, db):
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "api.acme.com",
            "mode": "active_recon", "tool": "httpx",
        })
        assert isinstance(out["command_preview"], list)
        # The preview keeps placeholders that depend on a live job.
        assert any("$INPUT_FILE$" in p for p in out["command_preview"])

    def test_rate_limit_honors_rule_hint(self, acme, db):
        # Scope rule hints rate_limit_rps_hint=5; active_recon default=10.
        # Effective = min(5, 10) = 5.
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "api.acme.com",
            "mode": "active_recon", "tool": "httpx",
        })
        assert out["rate_limit_hint"] == 5
        assert out["rate_limit_rps"] == 5

    def test_rules_of_engagement_excerpt(self, acme, db):
        out = routes.jobs_preflight(db, {
            "program_slug": acme.slug, "target": "api.acme.com",
            "mode": "active_recon", "tool": "httpx",
        })
        assert "DoS" in out["rules_of_engagement_excerpt"]

    def test_missing_fields_short_circuits(self, db):
        out = routes.jobs_preflight(db, {"program_slug": "x"})
        assert out["allowed"] is False
        assert "required" in out["reason"]


# ── dispatch routes ───────────────────────────────────────────────
class TestPhase15Dispatch:

    def test_workflows_list(self, db):
        status, body = server.dispatch("GET", "/api/v2/workflows", {}, None, db)
        assert status == 200
        assert body["count"] == len(R.OPERATOR_MODES)

    def test_workflow_detail(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/workflows/passive_recon", {}, None, db,
        )
        assert status == 200
        assert body["workflow"]["mode"] == "passive_recon"

    def test_workflow_detail_404(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/workflows/ghost", {}, None, db,
        )
        assert status == 404

    def test_preflight_route_allowed(self, acme, db):
        status, body = server.dispatch(
            "POST", "/api/v2/jobs/preflight", {},
            {"program_slug": acme.slug, "target": "api.acme.com",
             "mode": "passive_recon", "tool": "subfinder"}, db,
        )
        assert status == 200
        assert body["allowed"] is True

    def test_preflight_route_mode_no_longer_blocks_in_scope(self, acme, db):
        # Phase B: in-scope tool is always allowed; safety_class advisory
        # is in reason but does not block.
        status, body = server.dispatch(
            "POST", "/api/v2/jobs/preflight", {},
            {"program_slug": acme.slug, "target": "api.acme.com",
             "mode": "passive_recon", "tool": "nuclei"}, db,
        )
        assert status == 200
        assert body["allowed"] is True

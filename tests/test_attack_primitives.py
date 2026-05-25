"""Phase B — exploitation primitives.

Each module in ``attack/`` (other than the read-only mapper/taxonomy/
heatmap) exports a uniform ``run(target, opts) -> AttackResult``. These
tests verify:

  * The interface contract — every module exports ``run`` returning an
    ``AttackResult`` with the expected fields, and never raises into the
    caller (errors land in ``AttackResult.error``).
  * Input validation — malformed opts produce a clear error result, not a
    crash.
  * Pure-logic paths that don't require live HTTP (forge_alg_none,
    inject-url builder, etc.) behave as documented.

Network-touching code paths are mocked. Hunter integration is exercised
in tests/test_hunter_playbooks.py (Phase E will extend that file when
hunter starts calling these primitives by default).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from attack import (
    AttackError, AttackResult,
    replay, ssrf, jwt as jwt_mod, graphql, race, massassign,
)


# ── interface contract ────────────────────────────────────────────
@pytest.mark.parametrize("mod,name", [
    (replay,     "replay"),
    (ssrf,       "ssrf"),
    (jwt_mod,    "jwt"),
    (graphql,    "graphql"),
    (race,       "race"),
    (massassign, "massassign"),
])
def test_module_exports_run(mod, name):
    assert callable(getattr(mod, "run")), f"{name} must export run()"


@pytest.mark.parametrize("mod,bad_opts", [
    (replay,     {}),                       # no auth_a/auth_b
    (ssrf,       {}),                       # no interactsh_url
    (jwt_mod,    {}),                       # no token
    (graphql,    {}),                       # no target → handled by target= ""
    (race,       {}),                       # n defaults but target empty
    (massassign, {}),                       # no baseline_body
])
def test_bad_opts_returns_error_result(mod, bad_opts):
    """Bad input must yield an AttackResult with success=False and
    populated error — never a Python exception in the caller's stack."""
    r = mod.run("", bad_opts)
    assert isinstance(r, AttackResult)
    assert r.success is False
    assert r.confidence == 0.0
    assert r.error, f"{mod.__name__}.run with bad opts should set error"


# ── replay: differential semantics ────────────────────────────────
class TestReplay:
    def test_missing_auth_returns_error(self):
        r = replay.run("https://example.com/api/me", {"auth_a": {"X": "1"}})
        assert r.success is False
        assert "auth_b" in (r.error or "")

    def test_same_status_same_len_is_high_confidence(self, monkeypatch):
        # Patch _do_request so the test doesn't hit the network.
        def fake(url, method, headers, body, timeout):
            return {"status": 200, "len": 512, "ct": "application/json",
                    "body_head": "{}"}
        monkeypatch.setattr(replay, "_do_request", fake)
        r = replay.run("https://api/me", {
            "auth_a": {"Cookie": "a=1"}, "auth_b": {"Cookie": "b=2"},
        })
        assert r.success is True
        assert r.confidence >= 0.8
        assert "IDOR" in r.summary


# ── ssrf: url injection helper ────────────────────────────────────
class TestSSRF:
    def test_inject_adds_param_to_query(self):
        out = ssrf._inject("https://x/y?a=1", "url",
                           "http://abc.oast.live/")
        assert "url=http" in out
        # Original param preserved.
        assert "a=1" in out

    def test_missing_interactsh_short_circuits(self):
        r = ssrf.run("https://example.com/probe?u=", {})
        assert r.success is False
        assert "interactsh_url" in (r.error or "")


# ── jwt: forge + decode ───────────────────────────────────────────
class TestJWT:
    def test_split_jwt_raises_on_two_parts(self):
        with pytest.raises(ValueError):
            jwt_mod._split_jwt("aa.bb")

    def test_forge_alg_none_has_empty_signature(self):
        forged = jwt_mod._forge_alg_none({"sub": "1"})
        parts  = forged.split(".")
        assert len(parts) == 3
        assert parts[2] == ""

    def test_missing_token_returns_error(self):
        r = jwt_mod.run("https://api/me", {})
        assert r.success is False
        assert "token" in (r.error or "")


# ── graphql: alias query builder ──────────────────────────────────
class TestGraphQL:
    def test_build_alias_query_shape(self):
        q = graphql._build_alias_query("__typename", 3)
        assert q == "{a0:__typename a1:__typename a2:__typename}"

    def test_empty_target_returns_error(self):
        r = graphql.run("", {})
        assert r.success is False


# ── race: validation ──────────────────────────────────────────────
class TestRace:
    def test_n_out_of_range_rejected(self):
        r = race.run("https://x/", {"n": 1})
        assert r.success is False
        assert "between 2 and 200" in (r.error or "")

        r2 = race.run("https://x/", {"n": 999})
        assert r2.success is False


# ── massassign: baseline required ─────────────────────────────────
class TestMassAssign:
    def test_missing_baseline_returns_error(self):
        r = massassign.run("https://api/users/1", {})
        assert r.success is False
        assert "baseline_body" in (r.error or "")

    def test_echo_detection(self, monkeypatch):
        # Server echoes the injected 'role' field in its response body.
        # First call (baseline) returns clean body; subsequent calls
        # echo the injected field name.
        calls = {"n": 0}
        def fake(url, method, headers, body, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"status": 200, "len": 10, "body": "{}"}
            field_name = next(iter(set(body.keys()) - {"name"}), "")
            return {"status": 200, "len": 30,
                    "body": '{"name":"x","' + field_name + '":"echoed"}'}
        monkeypatch.setattr(massassign, "_do_request", fake)
        r = massassign.run("https://api/users/1", {
            "baseline_body": {"name": "x"},
            "extra_fields":  {"role": "admin"},
        })
        assert r.success is True
        assert "echoed" in r.summary or "role" in r.summary

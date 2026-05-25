"""
Wizard smoke tests. Verifies the text-mode wizard:

  - imports cleanly without Textual installed
  - run_text_wizard walks all 7 screens via scripted stdin
  - writes settings.json (with setup_complete marker) + scope file
    to ~/.config/reconforge
  - is_setup_complete() reflects the marker correctly
  - platform_handle is backfilled into pasted scope from identities
"""
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def test_text_wizard_writes_config(fake_home):
    """Drive run_text_wizard via stdin/stdout buffers."""
    from wizard.app import run_text_wizard, is_setup_complete
    assert is_setup_complete() is False
    script = "\n".join([
        "",                      # [1] welcome → continue
        "myh1",                  # [2] intigriti handle
        "",                      # [2] hackerone — skip
        "",                      # [2] bugcrowd — skip
        "",                      # [2] yeswehack — skip
        "",                      # [2] synack — skip
        "",                      # [3] tools → continue
        "ghp_test123",           # [4] github token
        "",                      # [4] interactsh default
        "",                      # [4] shodan — skip
        "api",                   # [5] llm mode
        "sk-test-1234",          # [5] api key
        '{"name": "demo", "platform": "intigriti", "in_scope": [{"type": "domain", "value": "demo.com"}]}',
        "",                      # [6] finish scope paste
        "",                      # [7] vault default
    ]) + "\n"
    rc = run_text_wizard(out=io.StringIO(), in_=io.StringIO(script))
    assert rc == 0

    settings = fake_home / ".config" / "reconforge" / "settings.json"
    assert settings.exists()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["setup_complete"] is True
    assert data["platform_identities"] == {"intigriti": "myh1"}
    assert data["api_keys"]["github_token"] == "ghp_test123"
    assert data["api_keys"]["interactsh_server"] == "https://oast.pro"
    assert "shodan_api_key" not in data["api_keys"]
    assert data["llm"]["mode"] == "api"
    assert data["llm"]["api_key"] == "sk-test-1234"

    # is_setup_complete now sees the marker
    assert is_setup_complete() is True

    # Scope file written and platform_handle backfilled from identities
    scope = fake_home / ".config" / "reconforge" / "scopes" / "demo.json"
    assert scope.exists()
    scope_doc = json.loads(scope.read_text())
    assert scope_doc["name"] == "demo"
    assert scope_doc["platform_handle"] == "myh1"


def test_text_wizard_local_mode_no_identities(fake_home):
    """All-empty identities + Ollama LLM. Verifies the wizard still
    completes cleanly when the user skips every optional input."""
    from wizard.app import run_text_wizard
    script = "\n".join([
        "",                  # [1] welcome
        "", "", "", "", "",  # [2] all 5 platform handles blank
        "",                  # [3] tools continue
        "", "", "",          # [4] all keys blank (interactsh has default)
        "local",             # [5] llm mode
        "",                  # [5] ollama url default
        "",                  # [5] opus sub default
        "",                  # [5] haiku sub default
        "",                  # [6] scope paste — blank submission
        "",                  # [7] vault default
    ]) + "\n"
    rc = run_text_wizard(out=io.StringIO(), in_=io.StringIO(script))
    assert rc == 0
    data = json.loads(
        (fake_home / ".config" / "reconforge" / "settings.json").read_text()
    )
    assert data["setup_complete"] is True
    assert data["platform_identities"] == {}
    assert data["llm"]["mode"] == "local"
    assert data["llm"]["ollama_url"].startswith("http://localhost")


def test_module_imports_cleanly():
    """The wizard module must import without Textual installed."""
    import wizard.app as wa
    assert callable(wa.run_text_wizard)
    assert callable(wa.main)
    assert callable(wa.is_setup_complete)


def test_is_setup_complete_handles_missing_file(fake_home):
    from wizard.app import is_setup_complete
    assert is_setup_complete() is False


def test_intigriti_report_requires_handle():
    """submissions/intigriti.py must refuse to format a report when
    program.platform_handle is missing — silently dropping the
    X-Intigriti-Username header would violate program rules."""
    from submissions.intigriti import format_draft
    finding = {"title": "x", "vuln_class": "idor", "evidence": {}}
    with pytest.raises(ValueError, match="platform_handle"):
        format_draft(finding, {"platform": "intigriti"})


def test_intigriti_report_uses_program_handle():
    from submissions.intigriti import format_draft
    finding = {"title": "x", "vuln_class": "idor",
                "evidence": {"endpoint": "https://example.com/api"}}
    draft = format_draft(finding, {"platform": "intigriti",
                                    "platform_handle": "alice"})
    assert "X-Intigriti-Username: alice" in draft.body_md
    assert draft.extra["required_header"] == "X-Intigriti-Username: alice"

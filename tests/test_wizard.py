"""
Phase 11 — wizard smoke. Verifies the text-mode wizard:

  - imports cleanly without Textual installed
  - run_text_wizard walks all 5 screens via scripted stdin
  - writes settings.json + scope file to ~/.config/reconforge
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
    from wizard.app import run_text_wizard
    script = "\n".join([
        "",                      # welcome → continue
        "",                      # tools → continue
        "api",                   # llm mode
        "sk-test-1234",          # api key
        '{"name": "demo", "platforms": ["hackerone"], "in_scope": [{"type": "domain", "value": "demo.com"}]}',
        "",                      # finish scope paste (blank line)
        "",                      # vault default
    ]) + "\n"
    in_buf = io.StringIO(script)
    out_buf = io.StringIO()
    rc = run_text_wizard(out=out_buf, in_=in_buf)
    assert rc == 0
    output = out_buf.getvalue()
    assert "ReconForge first-run wizard" in output
    assert "Tool Detect" in output
    settings = fake_home / ".config" / "reconforge" / "settings.json"
    assert settings.exists()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["llm"]["mode"] == "api"
    assert data["llm"]["api_key"] == "sk-test-1234"
    scope = fake_home / ".config" / "reconforge" / "scopes" / "demo.json"
    assert scope.exists()
    assert json.loads(scope.read_text())["name"] == "demo"


def test_text_wizard_local_mode(fake_home):
    from wizard.app import run_text_wizard
    script = "\n".join([
        "", "",                  # welcome + tools
        "local",                 # llm mode
        "",                      # ollama url default
        "",                      # opus sub default
        "",                      # haiku sub default
        "{}",                    # scope (empty doc)
        "",                      # finish paste
        "",                      # vault default
    ]) + "\n"
    rc = run_text_wizard(out=io.StringIO(), in_=io.StringIO(script))
    assert rc == 0
    data = json.loads(
        (fake_home / ".config" / "reconforge" / "settings.json").read_text()
    )
    assert data["llm"]["mode"] == "local"
    assert data["llm"]["ollama_url"].startswith("http://localhost")


def test_module_imports_cleanly():
    """The wizard module must import without Textual installed."""
    import wizard.app as wa
    assert callable(wa.run_text_wizard)
    assert callable(wa.main)

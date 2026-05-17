"""
Textual TUI screens — Welcome → Tool Detect → LLM Setup → Scope Paste → Vault.

This module is imported only when Textual is available; the parent
``wizard.app`` falls back to the plain-stdout wizard otherwise.

The 5-screen flow lives in ``ReconForgeWizard``; each screen is a
``Screen`` subclass. State carries forward via ``app.state``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.containers import Vertical
from textual.widgets import (
    Header, Footer, Button, Static, Input, TextArea, DataTable, Label,
)

from tools import detect


# ─────────────────────────────────────────────────────────────────
class WelcomeScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Welcome to ReconForge AI.\n\n"
            "This tool only runs against in-scope bug-bounty targets you are "
            "explicitly authorized to test. ATT&CK execution is fenced to "
            "Reconnaissance + Resource Development.\n\n"
            "Press Continue to begin first-run setup.",
            id="welcome-text",
        )
        yield Button("Continue", id="next", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self.app.push_screen(ToolDetectScreen())


class ToolDetectScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Tool Detection", classes="title")
        yield DataTable(id="tools-table")
        yield Static(id="install-plan")
        yield Button("Continue", id="next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        table: DataTable = self.query_one("#tools-table", DataTable)
        table.add_columns("Tool", "Status", "Method", "Path / Version")
        for s in detect.scan():
            status_icon = "OK" if s.installed else "MISSING"
            table.add_row(
                s.name, status_icon, s.install_method,
                s.path or (s.notes or "-"),
            )
        plan = detect.install_plan_human()
        self.query_one("#install-plan", Static).update(
            f"Install plan:\n\n{plan}"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self.app.push_screen(LLMSetupScreen())


class LLMSetupScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("LLM Backend", classes="title")
        yield Static("Pick how ReconForge talks to a model:")
        yield Button("Claude API",     id="api",   variant="primary")
        yield Button("Ollama (local)", id="local", variant="default")
        yield Button("Skip (degraded)", id="skip", variant="warning")
        yield Input(placeholder="API key (only if Claude API)", id="apikey", password=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "api":
            key = self.query_one("#apikey", Input).value
            self.app.state["llm"] = {"mode": "api", "api_key": key}
            self.app.push_screen(ScopePasteScreen())
        elif bid == "local":
            self.app.state["llm"] = {"mode": "local",
                                      "ollama_url": "http://localhost:11434",
                                      "opus_sub": "llama3.1:70b",
                                      "haiku_sub": "llama3.1:8b"}
            self.app.push_screen(ScopePasteScreen())
        elif bid == "skip":
            self.app.state["llm"] = {"mode": "skip"}
            self.app.push_screen(ScopePasteScreen())


class ScopePasteScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Paste Program Scope JSON", classes="title")
        yield TextArea(id="scope")
        yield Static(id="scope-validation")
        yield Button("Continue", id="next", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "next":
            return
        text = self.query_one("#scope", TextArea).text.strip()
        try:
            doc = json.loads(text) if text else {}
        except json.JSONDecodeError as e:
            self.query_one("#scope-validation", Static).update(
                f"[red]Invalid JSON: {e}[/red]"
            )
            return
        self.app.state["scope"] = doc
        self.app.push_screen(VaultPickScreen())


class VaultPickScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Vault Directory", classes="title")
        default = str(Path.home() / "Documents" / "BugBountyVault")
        yield Input(value=default, id="vault")
        yield Button("Finish", id="finish", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "finish":
            return
        path = self.query_one("#vault", Input).value
        self.app.state["vault"] = {"path": path}
        _write_config(self.app.state)
        self.app.exit(0)


def _write_config(state: Dict[str, Any]) -> None:
    cfg_dir = Path.home() / ".config" / "reconforge"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "settings.json").write_text(
        json.dumps({"llm": state.get("llm", {}),
                    "vault": state.get("vault", {})}, indent=2),
        encoding="utf-8",
    )
    scope = state.get("scope") or {}
    if scope:
        scopes_dir = cfg_dir / "scopes"
        scopes_dir.mkdir(parents=True, exist_ok=True)
        name = (scope.get("name") or "default").lower()
        (scopes_dir / f"{name}.json").write_text(
            json.dumps(scope, indent=2), encoding="utf-8",
        )


class ReconForgeWizard(App):
    CSS = """
    .title { text-style: bold; padding: 1 2; }
    """
    state: Dict[str, Any] = {}

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())

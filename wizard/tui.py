"""
Textual TUI screens — Welcome → Platform Identities → Tool Detect →
API Keys → LLM Setup → Scope Paste → Vault.

This module is imported only when Textual is available; the parent
``wizard.app`` falls back to the plain-stdout wizard otherwise.

Navigation: every screen after Welcome has a Back button. Values you
typed are saved into ``app.state`` on both Continue and Back, and each
screen rehydrates its inputs from ``app.state`` on mount — so back-then-
forward navigation does not lose what you typed. Final ``settings.json``
is written in ``_write_config`` with a ``setup_complete: true`` marker.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Button, Static, Input, TextArea, DataTable, Label,
)

from tools import detect

from .app import SUPPORTED_PLATFORMS, config_dir, settings_path


def _nav_row(*, show_back: bool = True, next_label: str = "Continue",
             next_variant: str = "primary") -> Horizontal:
    """Bottom-of-screen Back + Continue row.

    Welcome has no Back; everything after does. Continue is keyed ``next``
    so existing handlers (``event.button.id == "next"``) keep working.
    """
    if show_back:
        return Horizontal(
            Button("← Back", id="back", variant="default"),
            Button(next_label, id="next", variant=next_variant),
            classes="nav-row",
        )
    return Horizontal(
        Button(next_label, id="next", variant=next_variant),
        classes="nav-row",
    )


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
        yield _nav_row(show_back=False)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self.app.push_screen(PlatformIdentitiesScreen())


class PlatformIdentitiesScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Platform Identities", classes="title")
        yield Static(
            "Your researcher handle on each platform. Leave blank to skip.\n"
            "Used to build required headers (X-Intigriti-Username, etc.)."
        )
        prior: Dict[str, str] = self.app.state.get("platform_identities", {}) or {}
        for plat in SUPPORTED_PLATFORMS:
            yield Input(value=prior.get(plat, ""),
                        placeholder=f"{plat} handle", id=f"plat-{plat}")
        yield _nav_row()
        yield Footer()

    def _collect(self) -> None:
        identities: Dict[str, str] = {}
        for plat in SUPPORTED_PLATFORMS:
            val = self.query_one(f"#plat-{plat}", Input).value.strip()
            if val:
                identities[plat] = val
        self.app.state["platform_identities"] = identities

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self._collect()
            self.app.pop_screen()
        elif event.button.id == "next":
            self._collect()
            self.app.push_screen(ToolDetectScreen())


class ToolDetectScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Tool Detection", classes="title")
        yield DataTable(id="tools-table")
        yield Static(id="install-plan")
        yield _nav_row()
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
            f"Install plan (run in another shell):\n\n{plan}"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "next":
            self.app.push_screen(APIKeysScreen())


class APIKeysScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("API Keys & Tokens", classes="title")
        yield Static(
            "Optional but recommended. Stored locally with 0600 perms.\n"
            "Not stored in the web app database."
        )
        prior: Dict[str, str] = self.app.state.get("api_keys", {}) or {}
        yield Input(value=prior.get("github_token", ""),
                    placeholder="GitHub token (for github-subdomains)",
                    id="key-github", password=True)
        yield Input(value=prior.get("interactsh_server", "https://oast.pro"),
                    placeholder="Interactsh server URL",
                    id="key-interactsh")
        yield Input(value=prior.get("shodan_api_key", ""),
                    placeholder="Shodan API key (passive recon)",
                    id="key-shodan", password=True)
        yield _nav_row()
        yield Footer()

    def _collect(self) -> None:
        keys: Dict[str, str] = {}
        gh = self.query_one("#key-github", Input).value.strip()
        if gh:
            keys["github_token"] = gh
        it = self.query_one("#key-interactsh", Input).value.strip()
        if it:
            keys["interactsh_server"] = it
        sh = self.query_one("#key-shodan", Input).value.strip()
        if sh:
            keys["shodan_api_key"] = sh
        self.app.state["api_keys"] = keys

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self._collect()
            self.app.pop_screen()
        elif event.button.id == "next":
            self._collect()
            self.app.push_screen(LLMSetupScreen())


class LLMSetupScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("LLM Backend", classes="title")
        yield Static("Pick how ReconForge talks to a model:")
        yield Button("Claude API",     id="api",   variant="primary")
        yield Button("Ollama (local)", id="local", variant="default")
        yield Button("Skip (degraded)", id="skip", variant="warning")
        prior_llm: Dict[str, Any] = self.app.state.get("llm", {}) or {}
        yield Input(value=prior_llm.get("api_key", ""),
                    placeholder="API key (only if Claude API)",
                    id="apikey", password=True)
        yield _nav_row(next_label="Skip (use buttons above)", next_variant="default")
        yield Footer()

    def _advance(self, llm: Dict[str, Any]) -> None:
        self.app.state["llm"] = llm
        self.app.push_screen(ScopePasteScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "back":
            self.app.pop_screen()
            return
        if bid == "api":
            key = self.query_one("#apikey", Input).value
            self._advance({"mode": "api", "api_key": key})
        elif bid == "local":
            self._advance({"mode": "local",
                           "ollama_url": "http://localhost:11434",
                           "opus_sub":   "llama3.1:70b",
                           "haiku_sub":  "llama3.1:8b"})
        elif bid == "skip" or bid == "next":
            self._advance({"mode": "skip"})


class ScopePasteScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Paste Program Scope JSON (optional)", classes="title")
        yield Static(
            "Multi-line paste OK. Ctrl+Shift+V if your terminal needs it."
        )
        prior_scope = self.app.state.get("scope") or {}
        prior_text = ""
        if prior_scope:
            try:
                prior_text = json.dumps(prior_scope, indent=2)
            except (TypeError, ValueError):
                prior_text = ""
        yield TextArea(prior_text, id="scope")
        yield Static(id="scope-validation")
        yield _nav_row()
        yield Footer()

    def _collect(self) -> Dict[str, Any]:
        text = self.query_one("#scope", TextArea).text.strip()
        doc: Dict[str, Any] = {}
        if text:
            try:
                doc = json.loads(text)
            except json.JSONDecodeError as e:
                self.query_one("#scope-validation", Static).update(
                    f"[red]Invalid JSON: {e}[/red]"
                )
                # Save the raw text so going back doesn't drop it; validation
                # blocks Continue but Back should still preserve input.
                self.app.state["scope_raw"] = text
                return {"__invalid__": True}
            # Backfill platform_handle from identities collected earlier.
            ids = self.app.state.get("platform_identities", {}) or {}
            plat = (doc.get("platform") or "").lower()
            if plat in ids and not doc.get("platform_handle"):
                doc["platform_handle"] = ids[plat]
        self.app.state["scope"] = doc
        self.app.state.pop("scope_raw", None)
        return doc

    def on_mount(self) -> None:
        # If we previously held raw-invalid JSON, prefer that over the parsed
        # form so the user can fix the typo where they left it.
        raw = self.app.state.get("scope_raw")
        if raw:
            self.query_one("#scope", TextArea).text = raw

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            # Best-effort save, ignore validation errors going backward.
            try:
                self._collect()
            except Exception:
                pass
            self.app.pop_screen()
            return
        if event.button.id == "next":
            doc = self._collect()
            if doc.get("__invalid__"):
                return
            self.app.push_screen(VaultPickScreen())


class VaultPickScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Vault Directory", classes="title")
        default = str(Path.home() / "Documents" / "ResearchVault")
        prior_vault = (self.app.state.get("vault") or {}).get("path") or default
        yield Input(value=prior_vault, id="vault")
        yield _nav_row(next_label="Finish")
        yield Footer()

    def _collect(self) -> None:
        path = self.query_one("#vault", Input).value
        self.app.state["vault"] = {"path": path}

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self._collect()
            self.app.pop_screen()
            return
        if event.button.id == "next":
            self._collect()
            _write_config(self.app.state)
            self.app.exit(0)


def _write_config(state: Dict[str, Any]) -> None:
    cfg_dir = config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    out_doc = {
        "setup_complete":      True,
        "platform_identities": state.get("platform_identities", {}),
        "api_keys":            state.get("api_keys", {}),
        "llm":                 state.get("llm", {}),
        "vault":               state.get("vault", {}),
    }
    sp = settings_path()
    sp.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    try:
        os.chmod(sp, 0o600)  # POSIX-only; no-op on Windows
    except OSError:
        pass
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
    .nav-row { height: 3; padding: 1 2; }
    .nav-row Button { margin-right: 2; }
    """
    state: Dict[str, Any] = {}

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())

    def action_go_back(self) -> None:
        # ESC pops back to the previous screen (no-op on Welcome since
        # the stack only has one entry).
        if len(self.screen_stack) > 1:
            self.pop_screen()

# ReconForge v0.2.0 — Operator Console UAT

Manual end-to-end test for the v3 operator console (Phases 13-20). Run
against a Parrot OS 6.x VM with Docker + the latest GHCR image pulled.

Pass criteria: every checked step in the walkthrough succeeds. Record
the result in `tests/e2e/smoke_history.md` with the v0.2.0 tag.

## Pre-conditions

- Parrot OS 6.x VM, 4 GB RAM minimum.
- Docker installed, daemon running.
- `reconforge` binary on PATH (from `installer/install.sh` curl|bash).
- Local data directory writable.
- One real bug-bounty program scope JSON ready to paste (e.g. a public
  Intigriti or HackerOne program with explicit safe-harbor language).
- Browser open against `http://localhost:8342/`.

## Walkthrough

### 1. First-run wizard
- [ ] `reconforge wizard` opens the Textual TUI (or Rich fallback).
- [ ] Tool detection screen lists ≥18 installed tools on a clean Parrot box.
- [ ] LLM setup accepts an Anthropic API key or selects Ollama local mode.
- [ ] Scope paste screen accepts the prepared JSON; preview shows
      in_scope + out_of_scope counts.
- [ ] Wizard exit returns to the shell cleanly.

### 2. SPA boot + program selector
- [ ] `http://localhost:8342/` renders the topbar + left nav + Mission
      Control landing on first load.
- [ ] Program selector in topbar lists the program created during the
      wizard.
- [ ] Scope indicator chip shows `N in · 0 blocked · M rules`.

### 3. Mission Control widgets
- [ ] **Selected program** card shows name, platform, bounty range,
      policy link.
- [ ] **Scope summary** donut chart renders with in/out/ambiguous bands
      (use a fresh program: donut may show empty until passive recon runs).
- [ ] **Toolchain** mini-card shows X / 24 installed.
- [ ] **Next best actions** is empty (Strategist hasn't run) or shows
      passive-recon recommendation if the wizard auto-queued one.
- [ ] **Active jobs** empty.
- [ ] **New findings**, **Reports ready**, **Recent assets** all show
      `dim` empty-state copy.

### 4. Scope workbench
- [ ] Navigate Scope → Target check.
- [ ] Enter an in-scope hostname → scope-badge shows green `IN SCOPE`.
- [ ] Enter an out-of-scope hostname (program's careers/marketing
      subdomain) → red `BLOCKED` with the matched rule.
- [ ] Enter an unrelated domain → yellow `REVIEW` (ambiguous).
- [ ] Pre-flight preview: pick a passive tool (subfinder) + passive_recon
      mode → modal renders APPROVED TO RUN with command preview.
- [ ] Pre-flight preview: switch tool to nuclei → modal renders BLOCKED
      with mode-violation reason.
- [ ] Blocked targets panel: empty initially (no scope refusals yet).

### 5. Run a passive recon job
- [ ] Submit a passive_recon job against the program's root domain.
- [ ] Mission Control's **Active jobs** populates with the running agents.
- [ ] **Recent assets** populates with discovered subdomains as recon
      completes.
- [ ] Each discovered asset shows the right scope-badge color.

### 6. Assets tree view
- [ ] Navigate Assets.
- [ ] Tree groups subdomains under the root domain.
- [ ] Click an in-scope host → right pane shows technologies, IPs,
      screenshot path (if gowitness ran).
- [ ] Search filter narrows the tree as typed (debounced).
- [ ] "With findings only" filter empties the tree if Hunter hasn't run.

### 7. Toolchain page
- [ ] Navigate Toolchain.
- [ ] Tools grouped by category (Subdomain, DNS/HTTP, Screenshots,
      Vulnerability, Fuzzing, API, GraphQL, Cloud, JS).
- [ ] "Re-check tools" button forces a fresh probe (status=cache header
      gone).
- [ ] Copy-install-command button on a missing tool copies the apt /
      go install command to clipboard.

### 8. Triage board
- [ ] Navigate Findings.
- [ ] After Hunter has run, the Kanban board shows cards in `new`
      column with confidence chips.
- [ ] Drag a card from `new` → `needs_review` → board updates and the
      finding row's status flips.
- [ ] Click a card → finding detail page opens.

### 9. Finding detail tabs
- [ ] Overview tab shows CVSS + readiness checklist (mostly ✗ on a
      fresh finding).
- [ ] Raw Evidence tab lists observed/inferred rows in monospace.
- [ ] AI Analysis tab lists ai_hypothesis rows with Verify buttons.
- [ ] Click Verify → row flips to verified, page refreshes, the row
      moves to the Raw tab.
- [ ] Taxonomy tab shows ATT&CK + CWE + OWASP entries.
- [ ] Manual Verification tab renders the curated checklist for the
      vuln_class (IDOR / mass-assignment / XSS / etc.).
- [ ] Drafts tab lists per-platform submission drafts.

### 10. Report quality gate
- [ ] Open a draft via Reports or via the Drafts tab in finding detail.
- [ ] Quality gate widget shows 10 checks; at least the "operator
      reviewed" check fails on first load.
- [ ] Manually complete the missing sections in the draft body.
- [ ] Acknowledge the manual checklist → reviewed check passes.
- [ ] Inject a fake secret (`AKIAABCDEFGHIJKLMNOP`) → no_secrets check
      flips red.
- [ ] Remove the secret → gate goes all-green.

### 11. Submission preview
- [ ] Copy the draft body to clipboard (button enabled only when gate
      passes).
- [ ] Mark the draft `human_approved` via the approve toggle.
- [ ] Approved drafts disappear from "Reports ready" on Mission Control.

### 12. OPSEC sanity
- [ ] Tail the access log for the test target — confirm rate-limit
      adherence matches the preflight envelope (5 req/s for the test
      program's hint).
- [ ] Confirm Intigriti header `X-Intigriti-Username: grover` was sent
      on every request (check Burp / proxy capture).
- [ ] Run `pgrep -af nuclei` while idle — no orphan scanner processes.

## Pass criteria for v0.2.0 tag

- All 12 sections complete on a Parrot 6.x VM.
- Test count ≥ 540 (currently 596 expected at v0.2.0 freeze).
- Legacy SPA still reachable behind `RECONFORGE_UI=legacy`.
- Memory file `project_reconforge_v3.md` updated with the smoke history
  entry.

## Known v0.2.0 limitations (deferred to v0.3.0 — Phases 21-25)

- Workflow library still hardcoded (YAML loader lands in Phase 21).
- HAR/Burp import not yet present (Phase 22).
- Mass-assignment / JS-XSS playbooks methodology-brief — Phase 22-23.
- Metasploit integration disabled by default; opt-in mode in Phase 24.
- Obsidian export still per-finding only; per-program tree in Phase 25.

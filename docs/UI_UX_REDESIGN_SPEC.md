# ReconForge UI/UX Redesign Spec

## Status

Design direction approved for implementation.

Lovable mockup reference:
https://lovable.dev/projects/b78d49c9-38e4-498b-bd9e-f6472616122e

## Mission

Upgrade ReconForge from a generic dark-blue toolkit into a modern
**cypherpunk bug bounty operations console**.

The redesign improves visual identity, operator workflow, navigation,
and information hierarchy without changing the underlying
security-tooling functionality. ReconForge should feel like a
serious, methodology-driven hunt cockpit — not a generic dark-blue/cyan
SaaS dashboard.

The app should answer five questions at all times:

1. What target am I working?
2. What phase of the methodology am I in?
3. What commands or tools are relevant right now?
4. What evidence have I collected?
5. What should I do next?

## Non-negotiables

- **Do not remove** any existing app functionality. Every existing
  `/api/*` endpoint stays wired. Every tool in `_DEFAULT_TOOLS`
  remains configurable.
- **Do not alter** generated command semantics.
- **Do not add** live scanning, automated exploitation, or external
  execution behavior as part of this UI pass.
- **Do not reference** mentor figures, course creators, influencers,
  or outside companies in UI copy.
- **Do not use** dark blue / cyan as the dominant visual identity.
- Keep tone **professional, tactical, operator-focused**.
- All aggressive / active workflows remain explicitly user-initiated
  and clearly labeled.

## Methodology flow

The app guides operators through the bug bounty kill chain:

```
Target Intake
  → Scope Validation
    → Passive Recon
      → Active Recon
        → Asset Mapping
          → Fingerprinting
            → Vulnerability Testing
              → Evidence Collection
                → Report Export
```

## Color system

Graphite/gray base; purple primary; green success; yellow processing;
red error.

```css
:root {
  --bg-main:           #101114;
  --bg-elevated:       #17181d;
  --bg-panel:          #202127;
  --bg-panel-soft:     #262832;

  --border-muted:      #343743;
  --border-active:     #9b5cff;

  --text-primary:      #f2f3f7;
  --text-secondary:    #a7aab5;
  --text-muted:        #6f7380;

  --accent-purple:     #9b5cff;
  --accent-purple-soft: rgba(155, 92, 255, 0.18);

  --status-success:    #39ff88;
  --status-processing: #ffcf4a;
  --status-error:      #ff3b5c;

  --status-passive:    #8d95a8;
  --status-active:     #9b5cff;
  --status-aggressive: #ff3b5c;
}
```

### Color usage rules

**Purple** — active navigation, current phase, focus states, primary
buttons, command palette selection, active borders.

**Green** — completed steps, saved evidence, copied commands, export
complete, valid scope.

**Yellow** — processing, paused, needs review, pending state.

**Red** — error, invalid target, scope violation, destructive state,
aggressive risk badge.

**Gray** — base UI, panel backgrounds, inactive nav, muted text,
structural borders.

## Typography

Two-font system.

| Use | Font family |
|---|---|
| UI chrome, navigation, labels, body | Sans-serif: Inter, Geist, IBM Plex Sans, or system default |
| Commands, logs, palette shortcuts, terminal areas | Monospace: JetBrains Mono, IBM Plex Mono, Fira Code, or system mono |

```
Page title:        Sans, 24–32px, semibold
Panel title:       Sans, 14–18px, uppercase/small caps
Body text:         Sans, 13–15px
Command text:      Mono, 13–14px
Log/output text:   Mono, 12–13px
Status badges:     Mono, 11–12px, uppercase
```

## App shell

```
┌──────────────────────────────────────────────────────────────┐
│ Header: ReconForge | Target | Phase | Risk | ⌘K Palette     │
├───────────────┬──────────────────────────────────────────────┤
│ Sidebar       │ Main Workspace                               │
│ (methodology- │                                              │
│  first nav)   │ Phase / Page content                         │
│               │ Command Forge / Map / Evidence / Export      │
│               │                                              │
├───────────────┴──────────────────────────────────────────────┤
│ Bottom Activity Console (minimizable)                        │
└──────────────────────────────────────────────────────────────┘
```

### Header

Persistent. Shows:

- ReconForge brand
- Current target
- Current methodology phase
- Current risk mode
- Workspace / export status
- Command palette trigger (⌘K / Ctrl+K)

Example:
```
ReconForge  |  target: example.com  |  phase: Passive Recon  |  mode: PASSIVE  |  ⌘K
```

### Sidebar (methodology-first)

```
DASHBOARD

TARGET
  Intake
  Scope

RECON
  Passive Recon
  Active Recon
  URL Collection
  JS Mining

MAP
  Asset Map
  Tech Fingerprint
  Parameter Inventory

TEST
  XSS
  CORS
  LFI
  SQLi
  Auth / API
  Subdomain Takeover
  Sensitive Exposure

EVIDENCE
  Findings
  Notes
  Artifacts
  Timeline

REPORT
  Export
  Vault Sync

OPERATIONS
  Jobs
  Queue
  Workers
  Monitors
  Resources

ADMIN
  Settings
  Users
  Backups
```

Sidebar group states:

| State | Color |
|---|---|
| Inactive | gray |
| Current | purple (border + accent) |
| Complete | green check |
| Processing / paused | yellow dot |
| Error | red marker |

The OPERATIONS and ADMIN groups preserve all current ReconForge
functionality (jobs, queue, workers, settings, users, backups,
monitors, resources). The methodology groups above them are the new
operator-flow primary navigation.

### Bottom activity console

Persistent but minimizable.

**Expanded:**
```
┌─ Activity Console ───────────────────────────────────────────┐
│ [12:04:22] target loaded: example.com                        │
│ [12:05:11] command copied: subfinder passive enumeration     │
│ [12:07:38] evidence note created: live-hosts.md              │
│ [12:09:04] export complete: ResearchVault/BugBounty/example.com │
└──────────────────────────────────────────────────────────────┘
```

**Minimized:**
```
Console: 4 events | Last: command copied | Expand
```

Log color rules:

| Color | Meaning |
|---|---|
| Green | completed / saved / copied / exported |
| Yellow | processing / paused / waiting |
| Red | error / scope problem |
| Purple | selected / current workflow |
| Gray | normal activity |

### Command palette

Global. Triggers: `Ctrl+K`, `Cmd+K`, `/`.

Actions include:

- Load target
- Go to Passive Recon
- Go to Active Recon
- Go to XSS / CORS / LFI / SQLi / Auth / Takeover
- Open Findings
- Export to vault
- Toggle guide mode
- Toggle bottom console

Visual:

```
┌─ Command Palette ─────────────────────────────┐
│ > xss                                         │
├───────────────────────────────────────────────┤
│ Run XSS methodology guide              TEST   │
│ Generate reflected XSS commands        CMD    │
│ Open XSS evidence notes                NOTE   │
│ Export XSS finding template            EXPORT │
└───────────────────────────────────────────────┘
```

Graphite modal, purple active row, mono shortcut labels.

## Default startup: Target Intake

The app opens to **Target Intake**.

Fields:

- Program name
- Target domain
- Scope rules
- Out-of-scope entries
- Allowed testing level
- Workspace name
- Vault export path

Risk mode selector:

- Passive Only
- Passive + Active
- Full Authorized Testing

This selector is initially frontend state. It classifies visible
workflows and UI warnings; it does **not** change command semantics
or trigger scans.

## Kill-chain progress rail

Always visible. Shows the operator where they are in the hunt.

```
TARGET → SCOPE → PASSIVE → ACTIVE → MAP → TEST → EVIDENCE → REPORT
```

States: inactive (gray), current (purple), complete (green),
processing (yellow), error (red).

## Core components

### 1. Target Status Panel

```
Target:    example.com
Scope:     Validated
Mode:      Passive + Active
Workspace: example.com
Export:    ResearchVault/BugBounty/example.com
```

### 2. Command Forge

Centerpiece component on every methodology phase. Replaces generic
command cards.

```
┌─ Command Forge ───────────────────────────────┐
│ Phase: Passive Recon                          │
│ Risk:  PASSIVE                                │
│ Target: example.com                           │
│ Output: /ResearchVault/BugBounty/example.com/ │
├───────────────────────────────────────────────┤
│ $ subfinder -d example.com -all -recursive    │
│   > subdomains.txt                            │
├───────────────────────────────────────────────┤
│ [Copy]  [Save to Workspace]  [Add to Notes]  │
└───────────────────────────────────────────────┘
```

Optional collapsed helper text: **Why this matters**.

### 3. Recon Checklist

```
[✓] Target loaded
[✓] Scope defined
[ ] Passive subdomains generated
[ ] Live host filtering
[ ] URL collection
[ ] JS file mining
[ ] Parameter extraction
[ ] Evidence export
```

### 4. Metrics Cards

```
Live Hosts        URLs        JS Files
   128           4,219          83

Params      Interesting    Findings Drafted
 612            27               3
```

Mock / placeholder values are acceptable while backend wiring lands —
clearly label them as demo data until real telemetry replaces them.

### 5. Attack Surface Map

First pass: tree view (readable, export-friendly).

```
example.com
├── api.example.com
│   ├── /v1/auth
│   └── /v1/users
├── admin.example.com
└── static.example.com
    └── app.bundle.js
```

Graph visualization can come later.

### 6. Evidence Timeline

```
12:04  Target created
12:07  Passive recon command saved
12:13  Live host list added
12:18  XSS workflow opened
12:22  Finding note exported
```

### 7. Vault Export Panel

Vault structure:

```
ResearchVault/
└── BugBounty/
    └── example.com/
        ├── 00_Target.md
        ├── 01_Scope.md
        ├── 02_Recon.md
        ├── 03_Assets.md
        ├── 04_Testing.md
        ├── 05_Evidence.md
        ├── 06_Report_Draft.md
        ├── commands/
        ├── findings/
        └── artifacts/
```

Frontmatter convention:

```yaml
---
target: example.com
program:
scope:
risk_mode: passive_active
created:
status: active
tags:
  - bug-bounty
  - reconforge
  - recon
---
```

### 8. Bottom Activity Console

See [App shell → Bottom activity console](#bottom-activity-console).

### 9. Command Palette

See [App shell → Command palette](#command-palette).

## Optional guide mode

Off by default. Togglable from the header or command palette.

When enabled, methodology phases reveal short tactical helper text
under relevant components. Keep helper text short — operator-grade,
not tutorial-grade.

Example:

> **Why this matters**
> This step expands the known target surface before active probing.

## Copywriting rules

**Preferred:**

- Load Target
- Validate Scope
- Passive Recon / Active Recon
- Generate Commands
- Save Evidence
- Export Report
- Add to Notes
- Command Forge
- Activity Console

**Avoid:**

- Pwn / Hack the planet / Destroy target
- Elite mode / 1337 / leet
- Mentor / influencer / course / outside-company references
- Long legal disclaimers on every command card

## Safety / risk UX

Preserve authorized-testing framing without cluttering every action.

**Required:**

- Scope status visible at all times
- Risk level visible on every command
- PASSIVE / ACTIVE / AGGRESSIVE labels on every workflow card
- Aggressive workflows clearly marked
- Explicit user action required before any aggressive workflow

**Avoid:**

- Repetitive legal modals
- Blocking every command with warnings
- Long disclaimers on every card

## Implementation phases

### Phase 1 — Visual identity

- Replace dark-blue / cyan theme.
- Add graphite / purple / green / yellow / red tokens.
- Update panel / card styling to console modules.
- Add monospace command surfaces.
- Optional: subtle CRT / scanline texture in panel headers only.

### Phase 2 — App shell

- Top header (ReconForge | target | phase | risk | ⌘K).
- Methodology-first sidebar.
- Main workspace.
- Bottom activity console (minimizable).
- Command palette (Ctrl+K / Cmd+K / `/`).

### Phase 3 — Target-first workflow

- Target Intake as default landing.
- Scope validation panel.
- Risk mode selector.
- Target status panel.
- Kill-chain progress rail.

### Phase 4 — Methodology modules

- Move existing command/tool content into methodology-first sections.
- Add Command Forge presentation.
- Add optional guide panels.
- Add recon checklist.
- Asset surface tree.

### Phase 5 — Evidence / Export UX

- Findings board + finding cards.
- Evidence timeline.
- Vault export panel.
- Markdown export structure (00_Target.md … 06_Report_Draft.md +
  commands/, findings/, artifacts/).

## Acceptance criteria

- [ ] Existing functionality still works (login, jobs, settings,
  users, backups, monitors, resources).
- [ ] Existing command / tool content still renders.
- [ ] UI no longer feels like a dark-blue / cyan generic dashboard.
- [ ] Target Intake is the first / default screen.
- [ ] Sidebar follows the methodology flow (TARGET → RECON → MAP →
  TEST → EVIDENCE → REPORT).
- [ ] OPERATIONS and ADMIN groups preserve every prior tab.
- [ ] Command Forge component replaces generic command display
  styling.
- [ ] Bottom activity console exists and can minimize.
- [ ] Command palette exists (Ctrl+K / Cmd+K / `/`).
- [ ] Purple / green / yellow / red status system is consistent.
- [ ] Optional guide mode can be shown / hidden.
- [ ] Attack Surface Map tree is present.
- [ ] Recon Checklist is present.
- [ ] Evidence Timeline is present.
- [ ] Vault Export panel is present.
- [ ] No mentor, influencer, course, or outside-company references in
  UI copy.
- [ ] No real scanning / external execution added by this redesign.
- [ ] UI remains responsive on desktop and usable on tablet / mobile
  widths.
- [ ] All existing `/api/*` endpoints continue to function.

## PR checklist

Before merge:

- [ ] `bash -n` clean on any new shell helpers.
- [ ] `pytest tests/` passes (the test count from prior batches stays
  green).
- [ ] No new dependencies introduced (vanilla JS / CSS, no build
  step).
- [ ] Existing tools / commands still render.
- [ ] No live scanning / execution behavior added.
- [ ] Theme tokens centralized (CSS custom properties).
- [ ] Dark blue / cyan dominance removed.
- [ ] Target Intake loads first.
- [ ] Sidebar methodology flow implemented.
- [ ] Command Forge component implemented.
- [ ] Bottom console implemented and minimizable.
- [ ] Command palette implemented.
- [ ] Vault export UI represented.
- [ ] UI copy reviewed for professional tone.
- [ ] Responsive states checked.

## Reference

- Lovable mockup: https://lovable.dev/projects/b78d49c9-38e4-498b-bd9e-f6472616122e
- Existing operator doctrine: [`CLAUDE.md`](../CLAUDE.md)
- Recon playbook: [`docs/RECON_PLAYBOOK.md`](RECON_PLAYBOOK.md)
- Hunting playbook: [`docs/HUNTING_PLAYBOOK.md`](HUNTING_PLAYBOOK.md)
- Scope enforcement: [`scope_guard.py`](../scope_guard.py)

# E2E Smoke Test — Parrot OS

Final gate before declaring ReconForge v1 ready. Requires a real Parrot OS VM (6.x or current). All steps below assume you're SSHed into the VM as a non-root user with sudo.

## Pre-stage

1. **Fresh Parrot 6.x VM.** No prior ReconForge install.
2. **OWASP Juice Shop** running locally on `localhost:3000` for safe target practice:
   ```bash
   docker run --rm -d --name local-lab -p 3000:3000 example/vulnerable-lab
   ```
3. Confirm Docker works and the user has `docker` group membership (`groups | grep docker`). If not: `sudo usermod -aG docker $USER && newgrp docker`.

## Run

```bash
# 1. Install (use the artifact URL from the v0.1.0 release; pin works)
curl -sSL https://github.com/example-org/reconforge/releases/download/v0.1.0/install.sh | bash --auto-deps

# 2. First-run wizard
reconforge wizard
#   - Welcome → Continue
#   - Tool Detect → confirm installs (or skip; nuclei/httpx/subfinder must be present)
#   - LLM Setup:
#       Option A (CI key available): paste Claude API key
#       Option B (no key): pick "Ollama (local)", default URL, defaults for substitutes
#   - Scope Paste: paste the local lab scope JSON from tests/e2e/scope_local_lab.json
#   - Vault Pick: default ~/Documents/ResearchVault

# 3. Start service
reconforge start
# wait ~5s, confirm http://localhost:8342 loads the SPA

# 4. Submit a domain
reconforge scan localhost:3000

# 5. Watch the agent panel in the SPA. Wait ~5–10 minutes for full pipeline.
```

## Pass criteria

Run the verification harness:

```bash
bash tests/e2e/run_smoke.sh
```

It checks each item in `tests/e2e/expected_artifacts.json` and prints a PASS / FAIL summary. Specifically:

1. `ResearchVault/01-Programs/local-lab/strategist_plan.md` exists, non-empty.
2. At least one `BUG-local-lab-001.md` (or higher) under that folder.
3. `findings` table has ≥1 row with `cvss_score IS NOT NULL AND cvss_score > 0`.
4. `attack_techniques` table covers ≥3 distinct tactics.
5. `submission_drafts` table has ≥1 row per platform listed in the scope (Juice Shop scope = `hackerone` + `bugcrowd`; so ≥2 drafts per finding).
6. `GET /api/attack/heatmap?job=<id>` returns the 14-tactic JSON with non-empty `total_findings`.
7. The `submission_drafts.human_approved` column is `0` for every row (no auto-submission).

## Ollama-mode regression

After the API-mode run succeeds, repeat against a second domain with `llm.mode` flipped to `local`. Verify:

- `recon_summary.fallback == "legacy_linear"` in `agent_memory` for the new job.
- All six agents still produce output (Strategist/Analyst/Reporter switch to the configured local substitutes).

## Documenting deltas

After every run, write a one-paragraph delta into `tests/e2e/smoke_history.md`:

```
## YYYY-MM-DD — operator initials — host (Parrot version, Docker version)
- Outcome: PASS / FAIL
- Total cost: $X.XX
- Findings count: N
- ATT&CK tactics covered: M
- Notable deltas: <any tool/version drift, model changes, surprises>
```

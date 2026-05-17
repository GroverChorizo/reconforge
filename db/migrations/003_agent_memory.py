"""003 — agent memory + per-step run audit.

agent_memory: shared scratchpad. Strategist writes its plan here under
(job_id, 'strategist', 'plan_v1'); Recon reads its signal set under
(job_id, 'recon', 'signals'); etc. UNIQUE(job_id, agent, key) gives
idempotent overwrite via INSERT OR REPLACE.

agent_runs: one row per LLM call. Token counts + cost_usd feed the per-job
$5 cap (Phase 9). status transitions running → completed | failed; error
captured for triage.
"""

name = "003_agent_memory"

_SQL = """
CREATE TABLE IF NOT EXISTS agent_memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL,
    agent       TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(job_id, agent, key)
);
CREATE INDEX IF NOT EXISTS idx_memory_job   ON agent_memory(job_id);
CREATE INDEX IF NOT EXISTS idx_memory_agent ON agent_memory(job_id, agent);

CREATE TABLE IF NOT EXISTS agent_runs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id             TEXT NOT NULL,
    agent              TEXT NOT NULL,
    model              TEXT,
    status             TEXT DEFAULT 'running',
    prompt_tokens      INTEGER,
    completion_tokens  INTEGER,
    cost_usd           REAL,
    started_at         TEXT DEFAULT (datetime('now')),
    completed_at       TEXT,
    error              TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_job   ON agent_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON agent_runs(job_id, agent);
"""


def up(conn):
    conn.executescript(_SQL)


def down(conn):
    conn.executescript(
        "DROP TABLE IF EXISTS agent_runs; "
        "DROP TABLE IF EXISTS agent_memory;"
    )

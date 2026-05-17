"""004 — platform-specific submission drafts.

One row per (finding × platform). human_approved is the gate that releases
the draft for copy-to-clipboard in the SPA — auto-submission is out of
scope for v1 (CLAUDE.md doctrine: human-in-the-loop only).

obsidian_path is the absolute path to the BUG-XXX note the Reporter wrote
into BugBountyVault/01-Programs/<program>/ — populated when the Reporter
agent runs (Phase 9).
"""

name = "004_submission_drafts"

_SQL = """
CREATE TABLE IF NOT EXISTS submission_drafts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL,
    title           TEXT,
    body_md         TEXT,
    severity        TEXT,
    weakness        TEXT,
    obsidian_path   TEXT,
    human_approved  INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(finding_id, platform)
);
CREATE INDEX IF NOT EXISTS idx_drafts_finding  ON submission_drafts(finding_id);
CREATE INDEX IF NOT EXISTS idx_drafts_platform ON submission_drafts(platform);
"""


def up(conn):
    conn.executescript(_SQL)


def down(conn):
    conn.executescript("DROP TABLE IF EXISTS submission_drafts;")

"""006 — structured evidence + CWE/OWASP taxonomy + operator mode.

Three additions:

* ``finding_evidence`` — replaces the unstructured ``findings.evidence_json``
  blob with one row per (finding, key) labeled by source. Sources are a
  closed enum:
    observed      — tool stdout/stderr, DB row contents. Immutable.
    inferred      — parser/correlation logic output. Immutable.
    ai_hypothesis — LLM-generated. Mutable until verified.
    verified      — operator-confirmed. Frozen with verified_by/verified_at.

  The existing ``evidence_json`` column on ``findings`` is kept as a
  fallback view; the SPA renders ``finding_evidence`` when present and
  falls back to the legacy blob otherwise.

* ``finding_taxonomy`` — extends the ATT&CK mapping with CWE + OWASP.
  ATT&CK techniques continue to live in ``attack_techniques`` (built by
  ``attack.mapper``). CWE + OWASP rows are written by the new
  ``attack.taxonomy.persist_taxonomy_for_finding``.

* ``completed_jobs.mode`` — operator mode the job was launched in, used
  by Phase 15 pipeline gating. Defaults to ``passive_recon`` (safest).
"""

name = "006_evidence_modes_taxonomy"

_SQL = """
CREATE TABLE IF NOT EXISTS finding_evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    key          TEXT NOT NULL,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL
                 CHECK (source IN ('observed','inferred','ai_hypothesis','verified')),
    source_ref   TEXT,
    created_at   TEXT DEFAULT (datetime('now')),
    verified_by  TEXT,
    verified_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_source  ON finding_evidence(source);

CREATE TABLE IF NOT EXISTS finding_taxonomy (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    taxonomy     TEXT NOT NULL CHECK (taxonomy IN ('attack','cwe','owasp')),
    code         TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    confidence   REAL DEFAULT 1.0,
    source       TEXT NOT NULL DEFAULT 'rule'
                 CHECK (source IN ('rule','llm')),
    created_at   TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_taxonomy_finding ON finding_taxonomy(finding_id);
CREATE INDEX IF NOT EXISTS idx_taxonomy_kind    ON finding_taxonomy(taxonomy);
"""


def _has_column(conn, table: str, col: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any((r[1] if not isinstance(r, dict) else r["name"]) == col for r in rows)


def up(conn):
    conn.executescript(_SQL)
    if not _has_column(conn, "completed_jobs", "mode"):
        conn.execute(
            "ALTER TABLE completed_jobs ADD COLUMN mode TEXT DEFAULT 'passive_recon'"
        )
    conn.commit()


def down(conn):
    raise NotImplementedError("006 is not reversible")

"""002 — findings + ATT&CK technique tagging.

findings: one row per Hunter-discovered candidate, carried through Analyst
(CVSS/dedupe/chain) and Reporter (vault note + platform drafts).
parent_finding_id supports chain analysis where multiple findings combine
into a higher-severity composite (Phase 9).

attack_techniques: many-to-one to findings. Populated by attack.mapper
(Phase 3) — rule-first per vuln_class, LLM tiebreaker if confidence < 0.5.
"""

name = "002_findings_attack"

_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    bug_id               TEXT UNIQUE NOT NULL,
    job_id               TEXT,
    domain               TEXT NOT NULL,
    subdomain_id         INTEGER,
    vuln_class           TEXT NOT NULL,
    title                TEXT NOT NULL,
    description          TEXT,
    evidence_json        TEXT DEFAULT '{}',
    confidence           REAL DEFAULT 0.0,
    cvss_vector          TEXT,
    cvss_score           REAL,
    bounty_estimate_usd  INTEGER,
    parent_finding_id    INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    status               TEXT DEFAULT 'new',
    created_at           TEXT DEFAULT (datetime('now')),
    updated_at           TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_job    ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_class  ON findings(vuln_class);
CREATE INDEX IF NOT EXISTS idx_findings_parent ON findings(parent_finding_id);

CREATE TABLE IF NOT EXISTS attack_techniques (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tactic            TEXT NOT NULL,
    technique_id      TEXT NOT NULL,
    sub_technique_id  TEXT,
    confidence        REAL DEFAULT 0.5,
    rationale         TEXT,
    created_at        TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attack_finding ON attack_techniques(finding_id);
CREATE INDEX IF NOT EXISTS idx_attack_tactic  ON attack_techniques(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_tech    ON attack_techniques(technique_id);
"""


def up(conn):
    conn.executescript(_SQL)


def down(conn):
    conn.executescript(
        "DROP TABLE IF EXISTS attack_techniques; "
        "DROP TABLE IF EXISTS findings;"
    )

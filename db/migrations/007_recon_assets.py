"""007 — recon_assets: per-URL / JS / parameter discovery store.

Until now the pipeline ingested only host-level data (the `subdomains` table)
and nuclei signals. URLs, JS files, and parameters were written to the phase
run dirs on disk but never landed in a table, so the dashboard's URLs / JS /
Params tiles had no real source.

This table is the queryable home for those finer-grained assets, ingested at
phase-finalize the same way subs/httpx/nuclei are. `kind` discriminates the
asset class; UNIQUE(domain, kind, value) makes ingest idempotent across re-runs.
It is intentionally separate from the host-based "asset tree" (program_assets,
built from `subdomains`).
"""

name = "007_recon_assets"

_SQL = """
CREATE TABLE IF NOT EXISTS recon_assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    kind        TEXT NOT NULL,                 -- 'url' | 'js' | 'param'
    value       TEXT NOT NULL,
    source      TEXT DEFAULT '',               -- phase id that produced it
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(domain, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_recon_assets_domain_kind ON recon_assets(domain, kind);
CREATE INDEX IF NOT EXISTS idx_recon_assets_kind ON recon_assets(kind);
"""


def up(conn):
    conn.executescript(_SQL)
    conn.commit()


def down(conn):
    # forward-only by policy
    raise NotImplementedError("007 is not reversible")

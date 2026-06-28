"""008 — saved_commands: per-program custom command library.

Operators accumulate their own command lines while testing a program (a tweaked
ffuf invocation, a target-specific curl, a one-liner that worked last engagement).
Until now the app only auto-logged commands copied from the Command Forge into
the per-target history; there was no way to *author and keep* your own.

This table is the home for those saved commands, keyed by `target` (the program's
domain/workspace, the same key history and scope use). It is deliberately a
library — copy/recall only — not an execution queue.
"""

name = "008_saved_commands"

_SQL = """
CREATE TABLE IF NOT EXISTS saved_commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,                 -- program target/domain it belongs to
    name        TEXT DEFAULT '',               -- short label
    cmd         TEXT NOT NULL,                 -- the command line
    created_by  TEXT DEFAULT '',
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_saved_cmd_target ON saved_commands(target, created_at);
"""


def up(conn):
    conn.executescript(_SQL)
    conn.commit()


def down(conn):
    # forward-only by policy
    raise NotImplementedError("008 is not reversible")

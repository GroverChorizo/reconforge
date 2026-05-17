"""
ATT&CK taxonomy loader.

Reads the vendored data/attack-stix-mirror.json snapshot. The mapper
(attack.mapper) and the OPSEC boundary (core.opsec) both consume this.

Refresh policy: snapshot is updated manually via `reconforge attack refresh`
(Phase 11). v1 ships a curated subset focused on web/API/cloud findings —
all 14 tactics covered, ~50 techniques.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "attack-stix-mirror.json"


@lru_cache(maxsize=1)
def _load() -> Dict:
    return json.loads(_DATA_FILE.read_text(encoding="utf-8"))


# ── public surface ────────────────────────────────────────────────
def tactics() -> List[Dict]:
    """All 14 tactics in canonical ordering (Reconnaissance → Impact)."""
    return list(_load()["tactics"])


def techniques() -> List[Dict]:
    return list(_load()["techniques"])


def tactic_ids() -> List[str]:
    return [t["id"] for t in tactics()]


def get_tactic(tactic_id: str) -> Optional[Dict]:
    for t in tactics():
        if t["id"] == tactic_id:
            return t
    return None


def get_technique(technique_id: str) -> Optional[Dict]:
    """Looks up by exact ID; sub-techniques like T1552.005 work directly."""
    for t in techniques():
        if t["id"] == technique_id:
            return t
    return None


def tactic_name(tactic_id: str) -> str:
    t = get_tactic(tactic_id)
    return t["name"] if t else tactic_id


def split_sub(technique_id: str) -> tuple[str, Optional[str]]:
    """T1552.005 → ('T1552', 'T1552.005'). T1190 → ('T1190', None)."""
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        return parent, technique_id
    return technique_id, None


def techniques_for_tactic(tactic_id: str) -> List[Dict]:
    return [t for t in techniques() if tactic_id in t.get("tactics", [])]


def version() -> str:
    return _load().get("version", "unknown")

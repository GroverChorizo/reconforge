"""
ATT&CK heatmap aggregation.

Powers the v2 SPA grid (Phase 10). One row per (tactic) for a given job:
count of mappings, max confidence observed, and the top techniques by
frequency × confidence.

For the SPA we always return all 14 tactics (zero-fill missing ones) so
the front-end can render a stable 14-column grid.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from . import taxonomy


def aggregate(conn, job_id: str, top_n: int = 3) -> Dict[str, Dict]:
    """Aggregate attack_techniques for one job into a per-tactic summary.

    Returns:
        {
            "TA0001": {
                "name": "Initial Access",
                "count": 4,
                "max_confidence": 0.92,
                "top_techniques": [
                    {"id": "T1190", "name": "...", "count": 3, "max_confidence": 0.92},
                    ...
                ]
            },
            ...
        }
    Always contains all 14 tactics; tactics with zero hits get count=0.
    """
    rows = conn.execute(
        """
        SELECT at.tactic, at.technique_id, at.confidence
          FROM attack_techniques at
          JOIN findings f ON f.id = at.finding_id
         WHERE f.job_id = ?
        """,
        (job_id,),
    ).fetchall()

    # tactic_id -> {tech_id -> [confidences]}
    per_tech: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        per_tech[r["tactic"]][r["technique_id"]].append(float(r["confidence"]))

    out: Dict[str, Dict] = {}
    for tactic in taxonomy.tactics():
        tid = tactic["id"]
        tech_map = per_tech.get(tid, {})
        count = sum(len(v) for v in tech_map.values())
        max_conf = max((max(v) for v in tech_map.values()), default=0.0)
        tops = sorted(
            (
                {
                    "id": tech_id,
                    "name": (taxonomy.get_technique(tech_id) or {}).get("name", tech_id),
                    "count": len(confs),
                    "max_confidence": round(max(confs), 3),
                }
                for tech_id, confs in tech_map.items()
            ),
            key=lambda d: (d["count"], d["max_confidence"]),
            reverse=True,
        )[:top_n]
        out[tid] = {
            "name": tactic["name"],
            "count": count,
            "max_confidence": round(max_conf, 3),
            "top_techniques": tops,
        }
    return out


def total_findings(conn, job_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE job_id=?", (job_id,)
    ).fetchone()
    return int(row[0]) if row else 0

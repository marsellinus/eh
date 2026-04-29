#!/usr/bin/env python3
"""
Comparative analysis: before (baseline) vs after (fail2ban / crowdsec).

Computes delta metrics and effectiveness percentages for each protection mode.
Produces structured data suitable for slides and academic tables.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ComparisonDelta:
    """Delta between baseline and a protection mode."""
    mode: str                        # fail2ban | crowdsec
    # Attack reduction
    ssh_attempts_reduced_pct: float  # % fewer SSH attempts reaching server
    http_success_reduced_pct: float  # % fewer successful HTTP requests
    # Detection effectiveness
    blocked_ips: int
    detected_events: int
    detection_time_http_s: float
    detection_time_ssh_s: float
    # Resource cost
    cpu_overhead_pct: float          # extra CPU vs baseline
    # Verdict
    effectiveness_score: float       # 0–100, higher = better protection
    verdict: str                     # "Recommended" / "Acceptable" / "Insufficient"


def _pct_reduction(base: float, after: float) -> float:
    """Percentage reduction from base to after. Negative = increase."""
    if base == 0:
        return 0.0
    return round((base - after) / base * 100, 1)


def compare(rows: list[dict[str, Any]]) -> list[ComparisonDelta]:
    """
    Compare each non-baseline mode against the baseline.

    Args:
        rows: List of mode dicts from comparison_summary.json.

    Returns:
        List of ComparisonDelta, one per protection mode.
    """
    baseline = next((r for r in rows if r["mode"] == "baseline"), None)
    if not baseline:
        return []

    results: list[ComparisonDelta] = []

    for row in rows:
        if row["mode"] == "baseline":
            continue

        ssh_base  = baseline.get("ssh_success", 0) + baseline.get("ssh_fail", 0)
        ssh_after = row.get("ssh_success", 0) + row.get("ssh_fail", 0)
        ssh_red   = _pct_reduction(ssh_base, ssh_after)

        http_base  = baseline.get("http_2xx", 0)
        http_after = row.get("http_2xx", 0)
        http_red   = _pct_reduction(http_base, http_after)

        cpu_overhead = round(row.get("avg_cpu_percent", 0) - baseline.get("avg_cpu_percent", 0), 2)

        # Effectiveness: weighted combination of reductions + detection
        blocked = row.get("blocked_ips", 0)
        events  = row.get("detected_events", 0)
        det_http = row.get("detect_http_s", 0.0) or 0.0
        det_ssh  = row.get("detect_ssh_s",  0.0) or 0.0

        eff = (
            ssh_red  * 0.30 +
            http_red * 0.25 +
            min(blocked * 10, 30) +   # up to 30 pts for blocking
            min(events  * 5,  15)     # up to 15 pts for detection events
        )
        # Penalise if no detection at all
        if blocked == 0 and events == 0:
            eff *= 0.4
        effectiveness = round(min(100.0, max(0.0, eff)), 1)

        if effectiveness >= 60:
            verdict = "Recommended"
        elif effectiveness >= 30:
            verdict = "Acceptable"
        else:
            verdict = "Insufficient"

        results.append(ComparisonDelta(
            mode=row["mode"],
            ssh_attempts_reduced_pct=ssh_red,
            http_success_reduced_pct=http_red,
            blocked_ips=blocked,
            detected_events=events,
            detection_time_http_s=det_http,
            detection_time_ssh_s=det_ssh,
            cpu_overhead_pct=cpu_overhead,
            effectiveness_score=effectiveness,
            verdict=verdict,
        ))

    return results


def comparison_table(deltas: list[ComparisonDelta]) -> list[dict[str, Any]]:
    """Return list of dicts suitable for CSV/JSON export."""
    return [asdict(d) for d in deltas]

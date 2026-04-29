#!/usr/bin/env python3
"""
Simplified CVSS-like risk scorer for benchmark modes.

Produces a 0–10 score per mode based on:
  - Attack surface (successful HTTP + SSH requests reaching the server)
  - Detection capability (blocked IPs, detected events)
  - Response time (detection latency)
  - Resource overhead (CPU cost of the security tool)

Academic/research use only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ── Score weights (must sum to 1.0) ──────────────────────────────────────────
_W_EXPOSURE   = 0.35   # how many attacks got through
_W_DETECTION  = 0.30   # how well threats were detected/blocked
_W_RESPONSE   = 0.20   # how fast detection happened
_W_OVERHEAD   = 0.15   # CPU cost of the protection layer


@dataclass
class RiskScore:
    mode: str
    exposure_score: float    # 0=fully blocked, 10=fully exposed
    detection_score: float   # 0=no detection, 10=perfect detection
    response_score: float    # 0=no response, 10=instant response
    overhead_score: float    # 0=no overhead, 10=very high overhead
    composite: float         # weighted composite (lower = safer)
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    cvss_vector: str         # simplified vector string


def _severity(score: float) -> str:
    if score >= 8.0:  return "CRITICAL"
    if score >= 6.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score >= 2.0:  return "LOW"
    return "MINIMAL"


def score_mode(row: dict[str, Any], baseline: dict[str, Any] | None = None) -> RiskScore:
    """
    Compute a risk score for one benchmark mode row.

    Args:
        row:      Dict from comparison_summary.json for this mode.
        baseline: Baseline row for relative comparison (optional).

    Returns:
        RiskScore dataclass.
    """
    # ── Exposure: ratio of successful attacks vs baseline ────────────────────
    total_attacks = (row.get("ssh_fail", 0) + row.get("ssh_success", 0) +
                     row.get("http_2xx", 0) + row.get("http_403", 0) + row.get("http_other", 0))
    successful    = row.get("ssh_success", 0) + row.get("http_2xx", 0)

    if baseline:
        base_successful = (baseline.get("ssh_success", 0) + baseline.get("http_2xx", 0)) or 1
        exposure = min(10.0, (successful / base_successful) * 10.0)
    else:
        exposure = min(10.0, (successful / max(total_attacks, 1)) * 10.0)

    # ── Detection: blocked IPs + detected events, normalised ─────────────────
    blocked = row.get("blocked_ips", 0)
    events  = row.get("detected_events", 0)
    # Score 10 if blocked > 0, partial credit for events only
    if blocked > 0:
        detection = min(10.0, 5.0 + blocked * 1.5 + events * 0.5)
    elif events > 0:
        detection = min(4.9, events * 1.0)
    else:
        detection = 0.0

    # ── Response time: lower latency = higher score ───────────────────────────
    http_t = row.get("detect_http_s", 0.0) or 0.0
    ssh_t  = row.get("detect_ssh_s",  0.0) or 0.0
    avg_t  = (http_t + ssh_t) / max(sum(1 for t in [http_t, ssh_t] if t > 0), 1)
    if avg_t == 0:
        response = 0.0   # no detection at all
    elif avg_t <= 5:
        response = 10.0
    elif avg_t <= 15:
        response = 7.0
    elif avg_t <= 30:
        response = 4.0
    else:
        response = 2.0

    # ── Overhead: CPU cost (higher CPU = higher overhead score) ───────────────
    cpu = row.get("avg_cpu_percent", 0.0)
    overhead = min(10.0, cpu / 2.0)   # 20% CPU → score 10

    # ── Composite risk (exposure + overhead are "bad"; detection + response are "good") ──
    # Risk = weighted exposure + weighted overhead - weighted detection - weighted response
    # Clamp to [0, 10]
    raw = (_W_EXPOSURE * exposure
           + _W_OVERHEAD * overhead
           - _W_DETECTION * detection
           - _W_RESPONSE  * response)
    composite = round(max(0.0, min(10.0, raw + 5.0)), 2)  # shift so baseline ≈ 7

    vector = (f"AV:N/AC:L/PR:N/UI:N/"
              f"EXP:{exposure:.1f}/DET:{detection:.1f}/"
              f"RSP:{response:.1f}/OVH:{overhead:.1f}")

    return RiskScore(
        mode=row["mode"],
        exposure_score=round(exposure, 2),
        detection_score=round(detection, 2),
        response_score=round(response, 2),
        overhead_score=round(overhead, 2),
        composite=composite,
        severity=_severity(composite),
        cvss_vector=vector,
    )


def score_all(rows: list[dict[str, Any]]) -> list[RiskScore]:
    """Score all modes, using the baseline row as reference."""
    baseline = next((r for r in rows if r["mode"] == "baseline"), None)
    return [score_mode(r, baseline if r["mode"] != "baseline" else None) for r in rows]

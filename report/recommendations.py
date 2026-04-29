#!/usr/bin/env python3
"""
Security recommendations generator.

Produces structured, evidence-based recommendations from benchmark results.
Output is suitable for academic reports, seminar slides, and policy documents.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Recommendation:
    id: str           # e.g. "REC-01"
    priority: str     # CRITICAL / HIGH / MEDIUM / LOW
    category: str     # Detection | Hardening | Performance | Architecture
    finding: str      # What the data shows
    action: str       # Concrete remediation step
    evidence: str     # Metric that triggered this recommendation
    applicable_to: list[str]  # modes this applies to


def generate(
    rows: list[dict[str, Any]],
    deltas: list[dict[str, Any]],
    risk_scores: list[dict[str, Any]],
) -> list[Recommendation]:
    """
    Generate recommendations from benchmark data.

    Args:
        rows:        comparison_summary rows (all modes).
        deltas:      comparator output (protection modes only).
        risk_scores: risk_scorer output (all modes).

    Returns:
        Sorted list of Recommendation objects (CRITICAL first).
    """
    recs: list[Recommendation] = []
    _id = 0

    def _next_id() -> str:
        nonlocal _id
        _id += 1
        return f"REC-{_id:02d}"

    baseline = next((r for r in rows if r["mode"] == "baseline"), {})
    b_ssh_ok  = baseline.get("ssh_success", 0)
    b_http_ok = baseline.get("http_2xx", 0)

    # ── SSH brute-force exposure ──────────────────────────────────────────────
    if b_ssh_ok > 0:
        recs.append(Recommendation(
            id=_next_id(), priority="CRITICAL", category="Hardening",
            finding=f"SSH brute-force produced {b_ssh_ok} successful logins in baseline.",
            action="Disable password authentication; enforce SSH key-only login. "
                   "Set MaxAuthTries=3 in sshd_config.",
            evidence=f"ssh_success={b_ssh_ok} (baseline)",
            applicable_to=["baseline", "fail2ban", "crowdsec"],
        ))

    # ── No blocking detected ─────────────────────────────────────────────────
    for delta in deltas:
        if delta["blocked_ips"] == 0 and delta["detected_events"] == 0:
            recs.append(Recommendation(
                id=_next_id(), priority="HIGH", category="Detection",
                finding=f"{delta['mode'].upper()} produced 0 blocked IPs and 0 detected events.",
                action=f"Verify {delta['mode']} is correctly reading log files. "
                       "Check log path mounts in docker-compose and jail/acquisition config.",
                evidence="blocked_ips=0, detected_events=0",
                applicable_to=[delta["mode"]],
            ))

    # ── Detection latency ────────────────────────────────────────────────────
    for delta in deltas:
        http_t = delta.get("detection_time_http_s", 0.0) or 0.0
        ssh_t  = delta.get("detection_time_ssh_s",  0.0) or 0.0
        if http_t > 30 or ssh_t > 30:
            slow = "HTTP" if http_t > ssh_t else "SSH"
            t    = max(http_t, ssh_t)
            recs.append(Recommendation(
                id=_next_id(), priority="HIGH", category="Detection",
                finding=f"{delta['mode'].upper()} {slow} detection latency is {t}s (>30s threshold).",
                action="Reduce findtime and maxretry thresholds. "
                       "For Fail2Ban: lower findtime to 60s. "
                       "For CrowdSec: tune scenario leakspeed.",
                evidence=f"detect_{slow.lower()}_s={t}",
                applicable_to=[delta["mode"]],
            ))

    # ── High CPU overhead ────────────────────────────────────────────────────
    for row in rows:
        cpu = row.get("avg_cpu_percent", 0.0)
        if cpu > 15 and row["mode"] != "baseline":
            recs.append(Recommendation(
                id=_next_id(), priority="MEDIUM", category="Performance",
                finding=f"{row['mode'].upper()} consumes {cpu}% avg CPU during attack.",
                action="Profile the security daemon. For Fail2Ban: reduce log polling frequency. "
                       "For CrowdSec: limit active parsers to required collections only.",
                evidence=f"avg_cpu_percent={cpu}",
                applicable_to=[row["mode"]],
            ))

    # ── Comparative recommendation ───────────────────────────────────────────
    if len(deltas) >= 2:
        best = max(deltas, key=lambda d: d["effectiveness_score"])
        recs.append(Recommendation(
            id=_next_id(), priority="LOW", category="Architecture",
            finding=f"{best['mode'].upper()} achieved the highest effectiveness score "
                    f"({best['effectiveness_score']:.1f}/100) among tested solutions.",
            action=f"Deploy {best['mode'].upper()} as the primary intrusion prevention layer. "
                   "Combine with SSH key-only auth and nginx rate limiting for defence-in-depth.",
            evidence=f"effectiveness_score={best['effectiveness_score']}",
            applicable_to=[best["mode"]],
        ))

    # ── General hardening (always) ───────────────────────────────────────────
    recs.append(Recommendation(
        id=_next_id(), priority="MEDIUM", category="Hardening",
        finding="HTTP flood reached the application layer in all modes.",
        action="Add nginx rate limiting (limit_req_zone) and connection limits (limit_conn). "
               "Consider a WAF (ModSecurity) for layer-7 protection.",
        evidence=f"http_2xx={b_http_ok} (baseline)",
        applicable_to=["baseline", "fail2ban", "crowdsec"],
    ))

    # Sort: CRITICAL > HIGH > MEDIUM > LOW
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs.sort(key=lambda r: _order.get(r.priority, 9))
    return recs


def recommendations_to_dicts(recs: list[Recommendation]) -> list[dict[str, Any]]:
    return [asdict(r) for r in recs]

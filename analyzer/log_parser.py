#!/usr/bin/env python3
"""
Log parser for HTTP flood, SSH brute-force, and security snapshot files.

Refactored from scripts/parse_results.py — pure functions, no side effects.
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class HttpLogStats:
    http_2xx: int = 0
    http_403: int = 0
    http_other: int = 0


@dataclass
class SshLogStats:
    ssh_fail: int = 0
    ssh_success: int = 0


@dataclass
class SecuritySnapshot:
    detected_events: int = 0
    blocked_ips: int = 0
    detect_http_s: float = 0.0
    detect_ssh_s: float = 0.0
    raw: str = ""


def parse_http_log(path: Path) -> HttpLogStats:
    """Count HTTP response codes from an attack_http_*.log file."""
    if not path.exists():
        log.warning("[log_parser] HTTP log not found: %s", path)
        return HttpLogStats()

    text = path.read_text(encoding="utf-8", errors="ignore")
    success = len(re.findall(r"\b2\d\d\b", text))
    forbidden = len(re.findall(r"\b403\b", text))
    other = len(re.findall(r"\b[145]\d\d\b", text)) - forbidden
    stats = HttpLogStats(http_2xx=success, http_403=forbidden, http_other=max(other, 0))
    log.debug("[log_parser] HTTP %s → %s", path.name, stats)
    return stats


def parse_ssh_log(path: Path) -> SshLogStats:
    """Count SSH attempt outcomes from an attack_ssh_*.log file."""
    if not path.exists():
        log.warning("[log_parser] SSH log not found: %s", path)
        return SshLogStats()

    text = path.read_text(encoding="utf-8", errors="ignore")
    stats = SshLogStats(
        ssh_fail=len(re.findall(r"status=FAIL", text)),
        ssh_success=len(re.findall(r"status=SUCCESS", text)),
    )
    log.debug("[log_parser] SSH %s → %s", path.name, stats)
    return stats


def parse_security_snapshot(path: Path) -> SecuritySnapshot:
    """
    Parse a security_snapshot_*.json file produced by benchmark.py.

    Extracts blocked IP count, detected events, and detection times.
    """
    if not path.exists():
        log.warning("[log_parser] Snapshot not found: %s", path)
        return SecuritySnapshot()

    data = json.loads(path.read_text(encoding="utf-8"))
    raw = data.get("fail2ban_status") or data.get("crowdsec_metrics") or ""

    blocked = 0
    if "Banned IP list" in raw:
        m = re.search(r"Currently banned:\s*(\d+)", raw)
        if m:
            blocked = int(m.group(1))
    else:
        m = re.search(r"total decisions.*?(\d+)", raw, flags=re.IGNORECASE)
        if m:
            blocked = int(m.group(1))

    # Also count from the blocked_ips list in the snapshot itself
    if not blocked:
        blocked = len(data.get("blocked_ips", []))

    events = len(re.findall(r"(failed|ban|decision|alert)", raw, flags=re.IGNORECASE))
    detection = data.get("detection_seconds", {})

    snap = SecuritySnapshot(
        detected_events=events,
        blocked_ips=blocked,
        detect_http_s=float(detection.get("http") or 0.0),
        detect_ssh_s=float(detection.get("ssh") or 0.0),
        raw=raw[:8000],
    )
    log.debug("[log_parser] Snapshot %s → events=%d blocked=%d", path.name, events, blocked)
    return snap

#!/usr/bin/env python3
"""
Report generator: produces JSON and CSV comparison summaries.

Refactored from scripts/parse_results.py — accepts structured data
from the analyzer module instead of reading files directly.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ModeReport:
    """Aggregated metrics for a single benchmark mode."""
    mode: str
    # HTTP flood stats
    http_2xx: int = 0
    http_403: int = 0
    http_other: int = 0
    # SSH brute stats
    ssh_fail: int = 0
    ssh_success: int = 0
    # Resource usage
    avg_cpu_percent: float = 0.0
    avg_mem_percent: float = 0.0
    # Security detection
    detected_events: int = 0
    blocked_ips: int = 0
    detect_http_s: float = 0.0
    detect_ssh_s: float = 0.0


def generate_report(
    rows: list[ModeReport],
    out_dir: Path,
    prefix: str = "comparison_summary",
) -> tuple[Path, Path]:
    """
    Write JSON and CSV reports from a list of ModeReport objects.

    Args:
        rows:    One ModeReport per benchmark mode.
        out_dir: Directory to write output files.
        prefix:  Filename prefix (without extension).

    Returns:
        Tuple of (json_path, csv_path).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    data = [asdict(r) for r in rows]

    json_path = out_dir / f"{prefix}.json"
    csv_path = out_dir / f"{prefix}.csv"

    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("[report] JSON written: %s", json_path)

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
    log.info("[report] CSV written: %s", csv_path)

    return json_path, csv_path


def generate_comparison_summary(
    results_dir: Path,
    modes: list[str] | None = None,
) -> tuple[Path, Path]:
    """
    Build a comparison summary by reading existing result files from results_dir.

    This is the high-level entry point that mirrors parse_results.py behaviour.
    It imports analyzer functions to parse each mode's log/snapshot files.

    Args:
        results_dir: Path to the results/ directory.
        modes:       Modes to include; defaults to ["baseline", "fail2ban", "crowdsec"].

    Returns:
        Tuple of (json_path, csv_path).
    """
    import sys
    # Ensure project root is on sys.path so 'analyzer' resolves regardless of CWD
    _root = Path(__file__).resolve().parents[1]
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

    from analyzer.log_parser import parse_http_log, parse_ssh_log, parse_security_snapshot
    from analyzer.resource_metrics import parse_resource_csv

    modes = modes or ["baseline", "fail2ban", "crowdsec"]
    rows: list[ModeReport] = []

    for mode in modes:
        http = parse_http_log(results_dir / f"attack_http_{mode}.log")
        ssh = parse_ssh_log(results_dir / f"attack_ssh_{mode}.log")
        res = parse_resource_csv(results_dir / f"resource_{mode}.csv")
        sec = parse_security_snapshot(results_dir / f"security_snapshot_{mode}.json")

        rows.append(ModeReport(
            mode=mode,
            http_2xx=http.http_2xx,
            http_403=http.http_403,
            http_other=http.http_other,
            ssh_fail=ssh.ssh_fail,
            ssh_success=ssh.ssh_success,
            avg_cpu_percent=res.avg_cpu_percent,
            avg_mem_percent=res.avg_mem_percent,
            detected_events=sec.detected_events,
            blocked_ips=sec.blocked_ips,
            detect_http_s=sec.detect_http_s,
            detect_ssh_s=sec.detect_ssh_s,
        ))
        log.debug("[report] Parsed mode=%s", mode)

    json_path, csv_path = generate_report(rows, results_dir)

    # Print summary table to stdout
    print("\n=== Comparison Summary ===")
    for r in rows:
        print(f"  [{r.mode}] ssh_fail={r.ssh_fail} blocked={r.blocked_ips} "
              f"detect_http={r.detect_http_s}s detect_ssh={r.detect_ssh_s}s "
              f"cpu={r.avg_cpu_percent}%")
    print(f"\nSaved: {json_path}")
    print(f"Saved: {csv_path}")

    return json_path, csv_path


def print_report(data: list[dict[str, Any]]) -> None:
    """Pretty-print a list of mode report dicts to stdout."""
    print("\n=== Benchmark Report ===")
    for row in data:
        print(f"\n  Mode: {row.get('mode', '?').upper()}")
        for k, v in row.items():
            if k != "mode":
                print(f"    {k}: {v}")

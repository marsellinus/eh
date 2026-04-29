#!/usr/bin/env python3
"""
Academic report builder.

Reads comparison_summary.json + ml_nsl_kdd_metrics.json, runs all analysis
modules, and writes a structured JSON report + human-readable text summary
suitable for seminar slides and research papers.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def build(results_dir: Path, charts_dir: Path | None = None) -> Path:
    """
    Run full analysis pipeline and write academic_report.json.

    Args:
        results_dir: Path to results/ directory.
        charts_dir:  Where to save charts (defaults to results/charts/).

    Returns:
        Path to the written academic_report.json.
    """
    import sys
    _root = Path(__file__).resolve().parents[1]
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

    from report.risk_scorer    import score_all
    from report.comparator     import compare, comparison_table
    from report.recommendations import generate, recommendations_to_dicts
    from report.visualizer     import generate_all_charts

    charts_dir = charts_dir or results_dir / "charts"

    # ── Load base data ────────────────────────────────────────────────────────
    summary_path = results_dir / "comparison_summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(
            f"comparison_summary.json not found in {results_dir}. "
            "Run: python3 main.py --parse-only"
        )
    rows: list[dict[str, Any]] = json.loads(summary_path.read_text())

    ml_path = results_dir / "ml_nsl_kdd_metrics.json"
    ml_metrics: dict[str, Any] = (
        json.loads(ml_path.read_text()) if ml_path.exists() else {}
    )

    # ── Run analysis modules ──────────────────────────────────────────────────
    log.info("[report] Scoring risks...")
    risk_scores = score_all(rows)
    risk_dicts  = [asdict(r) for r in risk_scores]

    log.info("[report] Computing deltas...")
    deltas      = compare(rows)
    delta_dicts = comparison_table(deltas)

    log.info("[report] Generating recommendations...")
    recs      = generate(rows, delta_dicts, risk_dicts)
    rec_dicts = recommendations_to_dicts(recs)

    log.info("[report] Generating charts...")
    try:
        chart_paths = generate_all_charts(rows, risk_dicts, charts_dir)
        chart_files = [str(p.relative_to(_root)) for p in chart_paths]
    except Exception as e:
        log.warning("[report] Chart generation failed: %s", e)
        chart_files = []

    # ── Attack parameter justification ───────────────────────────────────────
    log.info("[report] Justifying attack parameters...")
    try:
        from analyzer.attack_param_justifier import justify_attack_parameters
        attack_justification = justify_attack_parameters()
    except Exception as e:
        log.warning("[report] Attack parameter justification failed: %s", e)
        attack_justification = {}

    # ── Assemble report ───────────────────────────────────────────────────────
    report: dict[str, Any] = {
        "meta": {
            "title": "Comparative Analysis: CrowdSec vs Fail2Ban on Docker Home Server",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "ethical-hacking-research-framework",
            "note": "For academic/research use only. All attacks performed in controlled lab.",
        },
        "summary": rows,
        "risk_scores": risk_dicts,
        "comparative_analysis": delta_dicts,
        "recommendations": rec_dicts,
        "ml_baseline": ml_metrics,
        "attack_parameter_justification": attack_justification,
        "charts": chart_files,
    }

    out_path = results_dir / "academic_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("[report] Academic report saved: %s", out_path)

    # ── Print human-readable summary ──────────────────────────────────────────
    _print_summary(report)
    return out_path


def _print_summary(report: dict[str, Any]) -> None:
    """Print a slide-ready text summary to stdout."""
    sep = "=" * 60

    print(f"\n{sep}")
    print(f"  {report['meta']['title']}")
    print(f"  Generated: {report['meta']['generated_at'][:19]}Z")
    print(sep)

    print("\n── RISK SCORES ─────────────────────────────────────────────")
    print(f"  {'Mode':<12} {'Composite':>10} {'Severity':<10} {'Exposure':>9} {'Detection':>10} {'Response':>9}")
    print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*9} {'-'*10} {'-'*9}")
    for r in report["risk_scores"]:
        print(f"  {r['mode']:<12} {r['composite']:>10.2f} {r['severity']:<10} "
              f"{r['exposure_score']:>9.2f} {r['detection_score']:>10.2f} {r['response_score']:>9.2f}")

    print("\n── COMPARATIVE ANALYSIS (vs Baseline) ──────────────────────")
    if report["comparative_analysis"]:
        print(f"  {'Mode':<12} {'SSH↓%':>7} {'HTTP↓%':>7} {'Blocked':>8} {'CPU+%':>7} {'Score':>7} {'Verdict'}")
        print(f"  {'-'*12} {'-'*7} {'-'*7} {'-'*8} {'-'*7} {'-'*7} {'-'*12}")
        for d in report["comparative_analysis"]:
            print(f"  {d['mode']:<12} {d['ssh_attempts_reduced_pct']:>7.1f} "
                  f"{d['http_success_reduced_pct']:>7.1f} {d['blocked_ips']:>8} "
                  f"{d['cpu_overhead_pct']:>7.2f} {d['effectiveness_score']:>7.1f} "
                  f"{d['verdict']}")
    else:
        print("  (no protection modes to compare)")

    print("\n── RECOMMENDATIONS ─────────────────────────────────────────")
    for r in report["recommendations"]:
        print(f"  [{r['priority']:>8}] {r['id']}  {r['category']}")
        print(f"           Finding: {r['finding'][:80]}")
        print(f"           Action:  {r['action'][:80]}")

    if report.get("ml_baseline"):
        ml = report["ml_baseline"]
        print("\n── ML BASELINE (NSL-KDD) ───────────────────────────────────")
        print(f"  Model:       {ml.get('model', 'N/A')}")
        print(f"  Accuracy:    {ml.get('accuracy', 0):.4f}")
        print(f"  Weighted F1: {ml.get('weighted_f1', 0):.4f}")
        print(f"  Macro F1:    {ml.get('macro_f1', 0):.4f}")
        print(f"  Train rows:  {ml.get('train_rows', 0):,}")

    if report.get("attack_parameter_justification"):
        apj = report["attack_parameter_justification"]
        params = apj.get("experiment_parameters", {})
        justif = apj.get("parameter_justification", {})
        print("\n── ATTACK PARAMETER JUSTIFICATION ──────────────────────────")
        print(f"  HTTP flood : {params.get('http_requests')} requests")
        for r in justif.get("http_flood", {}).get("rationale", []):
            print(f"    • {r[:90]}")
        print(f"  SSH brute  : {params.get('ssh_attempts')} attempts")
        for r in justif.get("ssh_brute_force", {}).get("rationale", []):
            print(f"    • {r[:90]}")

    if report.get("charts"):
        print("\n── CHARTS ──────────────────────────────────────────────────")
        for c in report["charts"]:
            print(f"  {c}")

    print(f"\n{sep}\n")

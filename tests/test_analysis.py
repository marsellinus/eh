"""Tests for report/risk_scorer.py, comparator.py, recommendations.py, visualizer.py."""

import json
import pytest
from pathlib import Path
from dataclasses import asdict

# ── Fixtures ──────────────────────────────────────────────────────────────────

ROWS = [
    {"mode": "baseline",  "http_2xx": 4800, "http_403": 8,  "http_other": 1616,
     "ssh_fail": 235, "ssh_success": 23, "avg_cpu_percent": 0.81, "avg_mem_percent": 0.06,
     "detected_events": 0, "blocked_ips": 0, "detect_http_s": 0.0, "detect_ssh_s": 0.0},
    {"mode": "fail2ban",  "http_2xx": 3000, "http_403": 5,  "http_other": 1010,
     "ssh_fail": 181, "ssh_success": 19, "avg_cpu_percent": 13.29, "avg_mem_percent": 0.06,
     "detected_events": 0, "blocked_ips": 0, "detect_http_s": 0.0, "detect_ssh_s": 0.0},
    {"mode": "crowdsec",  "http_2xx": 2400, "http_403": 4,  "http_other": 808,
     "ssh_fail": 116, "ssh_success": 13, "avg_cpu_percent": 1.54, "avg_mem_percent": 0.12,
     "detected_events": 2, "blocked_ips": 0, "detect_http_s": 0.0, "detect_ssh_s": 0.0},
]


# ── risk_scorer ───────────────────────────────────────────────────────────────

def test_score_all_returns_three():
    from report.risk_scorer import score_all
    scores = score_all(ROWS)
    assert len(scores) == 3


def test_score_composite_in_range():
    from report.risk_scorer import score_all
    for s in score_all(ROWS):
        assert 0.0 <= s.composite <= 10.0


def test_score_severity_valid():
    from report.risk_scorer import score_all
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}
    for s in score_all(ROWS):
        assert s.severity in valid


def test_score_cvss_vector_format():
    from report.risk_scorer import score_all
    for s in score_all(ROWS):
        assert s.cvss_vector.startswith("AV:N/")


def test_baseline_higher_exposure_than_crowdsec():
    from report.risk_scorer import score_all
    scores = {s.mode: s for s in score_all(ROWS)}
    # baseline has no detection → higher composite risk than crowdsec (which has events)
    assert scores["baseline"].exposure_score >= scores["crowdsec"].exposure_score


# ── comparator ───────────────────────────────────────────────────────────────

def test_compare_excludes_baseline():
    from report.comparator import compare
    deltas = compare(ROWS)
    modes = [d.mode for d in deltas]
    assert "baseline" not in modes
    assert len(deltas) == 2


def test_compare_ssh_reduction_positive():
    from report.comparator import compare
    for d in compare(ROWS):
        # Both protection modes have fewer SSH attempts than baseline
        assert d.ssh_attempts_reduced_pct > 0


def test_compare_effectiveness_in_range():
    from report.comparator import compare
    for d in compare(ROWS):
        assert 0.0 <= d.effectiveness_score <= 100.0


def test_compare_verdict_valid():
    from report.comparator import compare
    valid = {"Recommended", "Acceptable", "Insufficient"}
    for d in compare(ROWS):
        assert d.verdict in valid


def test_compare_no_baseline_returns_empty():
    from report.comparator import compare
    assert compare([]) == []
    assert compare([ROWS[0]]) == []  # only baseline → nothing to compare


# ── recommendations ───────────────────────────────────────────────────────────

def test_recommendations_not_empty():
    from report.comparator import compare, comparison_table
    from report.risk_scorer import score_all
    from report.recommendations import generate
    from dataclasses import asdict

    deltas = comparison_table(compare(ROWS))
    risks  = [asdict(s) for s in score_all(ROWS)]
    recs   = generate(ROWS, deltas, risks)
    assert len(recs) > 0


def test_recommendations_sorted_by_priority():
    from report.comparator import compare, comparison_table
    from report.risk_scorer import score_all
    from report.recommendations import generate
    from dataclasses import asdict

    deltas = comparison_table(compare(ROWS))
    risks  = [asdict(s) for s in score_all(ROWS)]
    recs   = generate(ROWS, deltas, risks)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    priorities = [order[r.priority] for r in recs]
    assert priorities == sorted(priorities)


def test_recommendations_have_required_fields():
    from report.comparator import compare, comparison_table
    from report.risk_scorer import score_all
    from report.recommendations import generate
    from dataclasses import asdict

    deltas = comparison_table(compare(ROWS))
    risks  = [asdict(s) for s in score_all(ROWS)]
    recs   = generate(ROWS, deltas, risks)

    for r in recs:
        assert r.id.startswith("REC-")
        assert r.action
        assert r.finding
        assert isinstance(r.applicable_to, list)


# ── visualizer ───────────────────────────────────────────────────────────────

def test_charts_created(tmp_path):
    from report.risk_scorer import score_all
    from report.visualizer import generate_all_charts
    from dataclasses import asdict

    risks = [asdict(s) for s in score_all(ROWS)]
    paths = generate_all_charts(ROWS, risks, tmp_path)

    assert len(paths) == 4
    for p in paths:
        assert p.exists()
        assert p.suffix == ".png"
        assert p.stat().st_size > 1000  # non-empty image


# ── academic_report (integration) ────────────────────────────────────────────

def test_build_academic_report(tmp_path):
    from report.academic_report import build

    # Write fixture comparison_summary.json
    (tmp_path / "comparison_summary.json").write_text(json.dumps(ROWS))

    out = build(tmp_path, charts_dir=tmp_path / "charts")
    assert out.exists()

    data = json.loads(out.read_text())
    assert "meta" in data
    assert "risk_scores" in data
    assert "comparative_analysis" in data
    assert "recommendations" in data
    assert len(data["risk_scores"]) == 3
    assert len(data["comparative_analysis"]) == 2
    assert len(data["recommendations"]) > 0

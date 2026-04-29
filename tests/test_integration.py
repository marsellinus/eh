"""
Integration test: full parse → report pipeline using fixture data.

Does NOT require Docker or live services. Uses the existing results/ files
if present, otherwise creates minimal fixture data.
"""

import json
import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _ensure_fixture(tmp_path: Path) -> Path:
    """Copy or create minimal result fixtures in tmp_path."""
    modes = ["baseline", "fail2ban", "crowdsec"]

    for mode in modes:
        # HTTP log
        (tmp_path / f"attack_http_{mode}.log").write_text(
            "request=1 code=200\nrequest=2 code=403\n"
        )
        # SSH log
        (tmp_path / f"attack_ssh_{mode}.log").write_text(
            "attempt=1 user=u pass=p status=FAIL\n"
            "attempt=2 user=u pass=p status=FAIL\n"
        )
        # Resource CSV
        (tmp_path / f"resource_{mode}.csv").write_text(
            "timestamp,container,cpu_percent,mem_usage,mem_percent\n"
            f"2026-01-01T00:00:00,nginx,{5 * (modes.index(mode) + 1)}%,100MiB / 1GiB,2%\n"
        )
        # Security snapshot
        snap = {
            "mode": mode,
            "fail2ban_status" if mode == "fail2ban" else "crowdsec_metrics": "",
            "detection_seconds": {"http": None, "ssh": None},
            "blocked_ips": [],
        }
        (tmp_path / f"security_snapshot_{mode}.json").write_text(json.dumps(snap))

    return tmp_path


def test_full_parse_pipeline(tmp_path):
    """generate_comparison_summary reads fixtures and writes JSON + CSV."""
    from report.generator import generate_comparison_summary

    _ensure_fixture(tmp_path)
    json_path, csv_path = generate_comparison_summary(tmp_path)

    assert json_path.exists()
    assert csv_path.exists()

    data = json.loads(json_path.read_text())
    assert len(data) == 3
    modes_found = {row["mode"] for row in data}
    assert modes_found == {"baseline", "fail2ban", "crowdsec"}


def test_parse_pipeline_with_real_results():
    """If results/ directory has real data, verify it parses without error."""
    if not RESULTS.exists():
        pytest.skip("results/ directory not found")

    has_any = any(RESULTS.glob("attack_http_*.log"))
    if not has_any:
        pytest.skip("No attack logs found in results/")

    from report.generator import generate_comparison_summary
    # Write to a temp location to avoid overwriting real results
    import tempfile, shutil
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for f in RESULTS.glob("*.log"):
            shutil.copy(f, tmp / f.name)
        for f in RESULTS.glob("*.csv"):
            shutil.copy(f, tmp / f.name)
        for f in RESULTS.glob("*.json"):
            shutil.copy(f, tmp / f.name)

        json_path, csv_path = generate_comparison_summary(tmp)
        assert json_path.exists()

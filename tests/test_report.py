"""Tests for report/generator.py."""

import json
import csv
import pytest
from pathlib import Path

from report.generator import ModeReport, generate_report


def _sample_rows() -> list[ModeReport]:
    return [
        ModeReport(mode="baseline", ssh_fail=235, ssh_success=23, avg_cpu_percent=0.81),
        ModeReport(mode="fail2ban", ssh_fail=181, blocked_ips=5, detect_ssh_s=7.2, avg_cpu_percent=13.29),
        ModeReport(mode="crowdsec", ssh_fail=116, blocked_ips=3, detect_ssh_s=4.1, avg_cpu_percent=1.54),
    ]


def test_generate_report_creates_files(tmp_path):
    rows = _sample_rows()
    json_path, csv_path = generate_report(rows, tmp_path)

    assert json_path.exists()
    assert csv_path.exists()


def test_generate_report_json_content(tmp_path):
    rows = _sample_rows()
    json_path, _ = generate_report(rows, tmp_path)

    data = json.loads(json_path.read_text())
    assert len(data) == 3
    assert data[0]["mode"] == "baseline"
    assert data[1]["blocked_ips"] == 5
    assert data[2]["detect_ssh_s"] == 4.1


def test_generate_report_csv_content(tmp_path):
    rows = _sample_rows()
    _, csv_path = generate_report(rows, tmp_path)

    with csv_path.open() as f:
        reader = list(csv.DictReader(f))

    assert len(reader) == 3
    assert reader[0]["mode"] == "baseline"
    assert float(reader[1]["avg_cpu_percent"]) == 13.29


def test_generate_report_custom_prefix(tmp_path):
    rows = _sample_rows()
    json_path, csv_path = generate_report(rows, tmp_path, prefix="test_output")

    assert json_path.name == "test_output.json"
    assert csv_path.name == "test_output.csv"


def test_mode_report_defaults():
    r = ModeReport(mode="baseline")
    assert r.http_2xx == 0
    assert r.detect_http_s == 0.0
    assert r.blocked_ips == 0

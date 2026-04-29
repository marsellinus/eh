"""Tests for analyzer/log_parser.py and analyzer/resource_metrics.py."""

import json
import pytest
from pathlib import Path

from analyzer.log_parser import parse_http_log, parse_ssh_log, parse_security_snapshot
from analyzer.resource_metrics import parse_resource_csv


# ── log_parser ────────────────────────────────────────────────────────────────

def test_parse_http_log_missing(tmp_path):
    stats = parse_http_log(tmp_path / "nonexistent.log")
    assert stats.http_2xx == 0
    assert stats.http_403 == 0


def test_parse_http_log_counts(tmp_path):
    log = tmp_path / "http.log"
    log.write_text(
        "request=1 code=200\n"
        "request=2 code=403\n"
        "request=3 code=200\n"
        "request=4 code=500\n"
        "request=5 code=403\n"
    )
    stats = parse_http_log(log)
    assert stats.http_2xx == 2
    assert stats.http_403 == 2
    assert stats.http_other >= 1


def test_parse_ssh_log_missing(tmp_path):
    stats = parse_ssh_log(tmp_path / "nonexistent.log")
    assert stats.ssh_fail == 0
    assert stats.ssh_success == 0


def test_parse_ssh_log_counts(tmp_path):
    log = tmp_path / "ssh.log"
    log.write_text(
        "attempt=1 user=u pass=p status=FAIL\n"
        "attempt=2 user=u pass=p status=FAIL\n"
        "attempt=3 user=u pass=p status=SUCCESS\n"
    )
    stats = parse_ssh_log(log)
    assert stats.ssh_fail == 2
    assert stats.ssh_success == 1


def test_parse_security_snapshot_missing(tmp_path):
    snap = parse_security_snapshot(tmp_path / "nonexistent.json")
    assert snap.detected_events == 0
    assert snap.blocked_ips == 0


def test_parse_security_snapshot_fail2ban(tmp_path):
    data = {
        "mode": "fail2ban",
        "fail2ban_status": "Currently banned: 3\nBanned IP list: 1.2.3.4 5.6.7.8 9.10.11.12",
        "detection_seconds": {"http": 4.5, "ssh": 7.2},
        "blocked_ips": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
    }
    snap_file = tmp_path / "snapshot.json"
    snap_file.write_text(json.dumps(data))
    snap = parse_security_snapshot(snap_file)
    assert snap.detect_http_s == 4.5
    assert snap.detect_ssh_s == 7.2
    assert snap.blocked_ips == 3


def test_parse_security_snapshot_uses_blocked_ips_list(tmp_path):
    """When raw status is empty, fall back to blocked_ips list length."""
    data = {
        "mode": "crowdsec",
        "crowdsec_metrics": "",
        "detection_seconds": {"http": None, "ssh": 3.1},
        "blocked_ips": ["10.0.0.1", "10.0.0.2"],
    }
    snap_file = tmp_path / "snapshot.json"
    snap_file.write_text(json.dumps(data))
    snap = parse_security_snapshot(snap_file)
    assert snap.blocked_ips == 2
    assert snap.detect_ssh_s == 3.1


# ── resource_metrics ──────────────────────────────────────────────────────────

def test_parse_resource_csv_missing(tmp_path):
    stats = parse_resource_csv(tmp_path / "nonexistent.csv")
    assert stats.avg_cpu_percent == 0.0
    assert stats.avg_mem_percent == 0.0


def test_parse_resource_csv_averages(tmp_path):
    csv_file = tmp_path / "resource.csv"
    csv_file.write_text(
        "timestamp,container,cpu_percent,mem_usage,mem_percent\n"
        "2026-01-01T00:00:00,nginx,10%,100MiB / 1GiB,5%\n"
        "2026-01-01T00:00:02,nginx,20%,200MiB / 1GiB,10%\n"
    )
    stats = parse_resource_csv(csv_file)
    assert stats.avg_cpu_percent == 15.0
    assert stats.avg_mem_percent == 7.5
    assert stats.samples == 2

"""Tests for scanner/port_scanner.py."""

import pytest
from unittest.mock import patch
from scanner.port_scanner import scan_ports, fingerprint_service, _assert_safe_target, ScanResult


def test_safe_target_allows_localhost():
    _assert_safe_target("127.0.0.1")  # should not raise


def test_safe_target_allows_private():
    _assert_safe_target("192.168.1.1")
    _assert_safe_target("10.0.0.1")
    _assert_safe_target("172.16.0.1")


def test_safe_target_blocks_public():
    with pytest.raises(ValueError, match="SAFETY"):
        _assert_safe_target("8.8.8.8")


def test_scan_returns_scan_result():
    # Patch socket.create_connection so no real network calls are made
    with patch("scanner.port_scanner.socket.create_connection") as mock_conn:
        mock_conn.side_effect = OSError("refused")
        result = scan_ports("127.0.0.1", ports=[22, 80])

    assert isinstance(result, ScanResult)
    assert result.host == "127.0.0.1"
    assert len(result.ports) == 2
    assert all(not p.open for p in result.ports)


def test_scan_detects_open_port():
    from unittest.mock import MagicMock
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("scanner.port_scanner.socket.create_connection", return_value=mock_sock):
        result = scan_ports("127.0.0.1", ports=[8080])

    assert len(result.open_ports()) == 1
    assert result.open_ports()[0].port == 8080


def test_fingerprint_blocks_public():
    with pytest.raises(ValueError, match="SAFETY"):
        fingerprint_service("1.2.3.4", 80)

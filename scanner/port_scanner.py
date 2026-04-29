#!/usr/bin/env python3
"""
Port scanner and service fingerprinting for controlled lab environments.

SECURITY NOTE: Only targets localhost / RFC-1918 private ranges.
Academic/research use only.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Allowed target ranges (localhost + RFC-1918 private)
_SAFE_PREFIXES = ("127.", "10.", "192.168.", "172.")

# Common ports to probe when no list is given
DEFAULT_PORTS = [22, 80, 443, 2222, 5000, 8081, 8443]

# Minimal banner-based fingerprints
_BANNERS: dict[int, str] = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    2222: "SSH",
    5000: "Flask/HTTP",
    8081: "HTTP-alt",
    8443: "HTTPS-alt",
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""


@dataclass
class ScanResult:
    host: str
    ports: list[PortResult] = field(default_factory=list)

    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]


def _assert_safe_target(host: str) -> None:
    """Raise ValueError if host is not a safe local/private address."""
    if not any(host.startswith(p) for p in _SAFE_PREFIXES):
        raise ValueError(
            f"[SAFETY] Target '{host}' is not a local/private address. "
            "This tool is for controlled lab environments only."
        )


def fingerprint_service(host: str, port: int, timeout: float = 1.5) -> str:
    """Grab a short banner from an open port for service identification."""
    _assert_safe_target(host)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256).decode(errors="ignore").strip()
                return banner[:120] if banner else _BANNERS.get(port, "unknown")
            except OSError:
                return _BANNERS.get(port, "unknown")
    except OSError:
        return ""


def scan_ports(
    host: str = "127.0.0.1",
    ports: list[int] | None = None,
    timeout: float = 0.5,
) -> ScanResult:
    """
    TCP connect scan against a local/private host.

    Args:
        host:    Target IP (must be localhost or RFC-1918).
        ports:   List of ports to scan; defaults to DEFAULT_PORTS.
        timeout: Per-port connection timeout in seconds.

    Returns:
        ScanResult with per-port open/closed status and service name.
    """
    _assert_safe_target(host)
    ports = ports or DEFAULT_PORTS
    result = ScanResult(host=host)

    log.debug("[scanner] Scanning %s on %d ports", host, len(ports))

    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                service = _BANNERS.get(port, "unknown")
                banner = fingerprint_service(host, port, timeout=timeout)
                result.ports.append(PortResult(port=port, open=True, service=service, banner=banner))
                log.debug("[scanner] %s:%d OPEN (%s)", host, port, service)
        except OSError:
            result.ports.append(PortResult(port=port, open=False))
            log.debug("[scanner] %s:%d closed", host, port)

    open_count = len(result.open_ports())
    log.info("[scanner] %s — %d/%d ports open", host, open_count, len(ports))
    return result

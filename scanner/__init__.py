"""Scanner module: port scanning and service fingerprinting."""
from .port_scanner import scan_ports, fingerprint_service

__all__ = ["scan_ports", "fingerprint_service"]

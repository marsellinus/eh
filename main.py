#!/usr/bin/env python3
"""
main.py — Unified controller for CrowdSec vs Fail2Ban research benchmark.

Replaces scripts/benchmark.py with a modular architecture that delegates
to scanner/, exploit/, analyzer/, and report/ packages.

Usage:
    python3 main.py [--modes baseline fail2ban crowdsec] [--scan] [--ml]
    python3 main.py --scan-only
    python3 main.py --parse-only
    python3 main.py --ml-only

SECURITY NOTE: All attack simulations target localhost only.
Academic/research use only.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── Project root (this file lives at project root) ──────────────────────────
ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
LOGS = ROOT / "logs"
BLOCK_FILE = LOGS / "blocked_ips.txt"
FAIL2BAN_JAILS = ["sshd-docker", "nginx-http-flood"]

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")


# ── Docker helpers ───────────────────────────────────────────────────────────

def _compose_cmd() -> list[str]:
    """Detect available docker compose command."""
    if shutil.which("docker"):
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
        if r.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        r = subprocess.run(["docker-compose", "version"], capture_output=True, check=False)
        if r.returncode == 0:
            return ["docker-compose"]
    raise RuntimeError("Docker Compose not found. Install docker-compose or the docker compose plugin.")


def _sh(cmd: list[str], optional: bool = False) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(cmd))
    res = subprocess.run(cmd, cwd=ROOT, check=False, text=True, capture_output=True)
    if res.returncode != 0 and not optional:
        if res.stdout.strip():
            log.error(res.stdout)
        if res.stderr.strip():
            log.error(res.stderr)
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res


def _stack_up(mode: str) -> None:
    compose = _compose_cmd()
    if mode == "baseline":
        _sh([*compose, "up", "-d", "--build"])
    elif mode == "fail2ban":
        _sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.fail2ban.yml", "up", "-d", "--build"])
    elif mode == "crowdsec":
        _sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.crowdsec.yml", "up", "-d", "--build"])
    else:
        raise ValueError(f"Unknown mode: {mode}")
    log.info("[docker] Stack '%s' started", mode)


def _stack_down(mode: str) -> None:
    compose = _compose_cmd()
    flags = ["-v", "--remove-orphans"]
    if mode == "baseline":
        _sh([*compose, "down", *flags], optional=True)
    elif mode == "fail2ban":
        _sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.fail2ban.yml", "down", *flags], optional=True)
    elif mode == "crowdsec":
        _sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.crowdsec.yml", "down", *flags], optional=True)
    log.info("[docker] Stack '%s' stopped", mode)


def _reset_environment() -> None:
    log.info("[env] Resetting environment...")
    _sh(["bash", "scripts/reset_environment.sh"])


# ── Blocked IP helpers ───────────────────────────────────────────────────────

def _get_fail2ban_ips() -> list[str]:
    blocked: list[str] = []
    for jail in FAIL2BAN_JAILS:
        res = _sh(["docker", "exec", "sec-fail2ban", "fail2ban-client", "status", jail], optional=True)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "Banned IP list" in line:
                    blocked.extend(line.split(":", 1)[-1].strip().split())
    return sorted(set(blocked))


def _get_crowdsec_ips() -> list[str]:
    res = _sh(["docker", "exec", "sec-crowdsec", "cscli", "decisions", "list", "-o", "json"], optional=True)
    if res.returncode != 0 or not res.stdout.strip():
        return []
    try:
        data = json.loads(res.stdout)
        return sorted({item.get("value", "").strip() for item in data if item.get("value")})
    except json.JSONDecodeError:
        return []


def _blocked_ips(mode: str) -> list[str]:
    if mode == "fail2ban":
        return _get_fail2ban_ips()
    if mode == "crowdsec":
        return _get_crowdsec_ips()
    return []


def _write_block_file(ips: list[str]) -> None:
    lines = [f"{ip} 1;" for ip in ips]
    BLOCK_FILE.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ── Detection timing ─────────────────────────────────────────────────────────

def _measure_detection(mode: str, attack_cmd: list[str], poll: float = 1.0) -> float | None:
    """Run attack_cmd and return seconds until first IP is blocked (or None)."""
    if mode == "baseline":
        subprocess.run(attack_cmd, cwd=ROOT, check=False)
        return None

    start = time.time()
    proc = subprocess.Popen(attack_cmd, cwd=ROOT)
    detected_at: float | None = None

    while proc.poll() is None:
        if _blocked_ips(mode):
            detected_at = time.time()
            break
        time.sleep(poll)

    proc.wait()
    if detected_at is None and _blocked_ips(mode):
        detected_at = time.time()

    return round(detected_at - start, 2) if detected_at else None


# ── Security snapshot ────────────────────────────────────────────────────────

def _collect_snapshot(mode: str) -> dict:
    snapshot: dict = {"mode": mode, "timestamp": time.time()}
    if mode == "fail2ban":
        res = _sh(["docker", "exec", "sec-fail2ban", "fail2ban-client", "status"], optional=True)
        snapshot["fail2ban_status"] = res.stdout if res.returncode == 0 else ""
    elif mode == "crowdsec":
        res = _sh(["docker", "exec", "sec-crowdsec", "cscli", "metrics"], optional=True)
        snapshot["crowdsec_metrics"] = res.stdout if res.returncode == 0 else ""
    return snapshot


# ── Scan phase ───────────────────────────────────────────────────────────────

def run_scan(host: str = "127.0.0.1") -> None:
    """Run port scan and print open services."""
    from scanner import scan_ports
    log.info("[scan] Scanning %s...", host)
    result = scan_ports(host)
    print(f"\n=== Port Scan: {host} ===")
    for p in result.ports:
        status = "OPEN" if p.open else "closed"
        svc = f" ({p.service})" if p.open else ""
        print(f"  {p.port}/tcp  {status}{svc}")
    print(f"\n  {len(result.open_ports())} open port(s) found")


# ── Benchmark mode ───────────────────────────────────────────────────────────

def run_mode(mode: str) -> None:
    """Execute a full benchmark cycle for one mode."""
    log.info("\n%s\n=== MODE: %s ===\n%s", "=" * 40, mode.upper(), "=" * 40)

    _reset_environment()
    _stack_up(mode)
    log.info("[%s] Waiting 12s for services to stabilise...", mode)
    time.sleep(12)

    # Start resource collection in background
    metrics_proc = subprocess.Popen(
        ["bash", "scripts/collect_metrics.sh", mode, "8", "2"], cwd=ROOT
    )

    # HTTP flood
    http_detect = _measure_detection(
        mode,
        ["bash", "scripts/attack_http_flood.sh",
         "http://127.0.0.1:8081/", "500", "25", f"results/attack_http_{mode}.log"],
    )
    log.info("[%s] HTTP detection time: %s", mode, f"{http_detect}s" if http_detect else "N/A")

    # SSH brute-force
    ssh_detect = _measure_detection(
        mode,
        ["python3", "scripts/attack_ssh_bruteforce.py",
         "--attempts", "40", "--output", f"results/attack_ssh_{mode}.log"],
    )
    log.info("[%s] SSH detection time: %s", mode, f"{ssh_detect}s" if ssh_detect else "N/A")

    metrics_proc.wait()

    # Collect and persist snapshot
    blocked = _blocked_ips(mode)
    _write_block_file(blocked)

    snapshot = _collect_snapshot(mode)
    snapshot["detection_seconds"] = {"http": http_detect, "ssh": ssh_detect}
    snapshot["blocked_ips"] = blocked
    snap_path = RESULTS / f"security_snapshot_{mode}.json"
    snap_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    log.info("[%s] Snapshot saved: %s", mode, snap_path)

    _stack_down(mode)


# ── Parse / report phase ─────────────────────────────────────────────────────

def run_parse(modes: list[str] | None = None) -> None:
    """Parse existing result files and generate comparison summary."""
    from report import generate_comparison_summary
    generate_comparison_summary(RESULTS, modes=modes)


# ── ML baseline phase ────────────────────────────────────────────────────────

def run_ml(dataset: str = "nsl_kdd") -> None:
    """Train RandomForest on the selected dataset and save metrics."""
    from analyzer import run_ml_baseline
    import json as _json

    log.info("[ml] Running ML baseline (dataset=%s)...", dataset)
    try:
        metrics = run_ml_baseline(dataset=dataset)
    except (FileNotFoundError, ImportError, ValueError) as e:
        log.error("[ml] %s", e)
        return

    dataset_slug = dataset.replace("_", "")
    out = RESULTS / f"ml_{dataset_slug}_metrics.json"
    out.write_text(_json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\n=== ML Baseline ({dataset}) ===")
    print(_json.dumps(metrics, indent=2))
    print(f"Saved: {out}")


# ── Academic report phase ────────────────────────────────────────────────────

def run_report() -> None:
    """Run full academic analysis: risk scores, comparison, charts, recommendations."""
    from report.academic_report import build
    log.info("[report] Building academic report...")
    try:
        out = build(RESULTS)
        log.info("[report] Done: %s", out)
    except FileNotFoundError as e:
        log.error("[report] %s", e)



def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CrowdSec vs Fail2Ban benchmark controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                          # full benchmark (all modes)
  python3 main.py --modes baseline         # baseline only
  python3 main.py --modes fail2ban crowdsec --scan
  python3 main.py --scan-only              # port scan only
  python3 main.py --parse-only             # regenerate reports from existing results
  python3 main.py --ml-only                # ML baseline only
  python3 main.py --modes crowdsec --ml    # crowdsec + ML
        """,
    )
    p.add_argument(
        "--modes", nargs="+",
        choices=["baseline", "fail2ban", "crowdsec"],
        default=["baseline", "fail2ban", "crowdsec"],
        help="Benchmark modes to run (default: all three)",
    )
    p.add_argument("--scan", action="store_true", help="Run port scan before benchmark")
    p.add_argument("--ml", action="store_true", help="Run ML baseline after benchmark")
    p.add_argument(
        "--dataset",
        choices=["nsl_kdd", "cicids", "custom"],
        default="nsl_kdd",
        help="Dataset untuk ML baseline: nsl_kdd (default), cicids, atau custom (log eksperimen)",
    )
    p.add_argument("--scan-only",    action="store_true", help="Only run port scan, then exit")
    p.add_argument("--parse-only",   action="store_true", help="Only regenerate comparison report")
    p.add_argument("--ml-only",      action="store_true", help="Only run ML baseline")
    p.add_argument("--report-only",  action="store_true", help="Only build academic report (risk + charts + recommendations)")
    p.add_argument("--report",       action="store_true", help="Build academic report after benchmark")
    p.add_argument("--host", default="127.0.0.1", help="Target host for port scan (default: 127.0.0.1)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    RESULTS.mkdir(parents=True, exist_ok=True)

    # ── Exclusive single-phase modes ─────────────────────────────────────────
    if args.scan_only:
        run_scan(args.host)
        return

    if args.parse_only:
        run_parse()
        return

    if args.ml_only:
        run_ml(args.dataset)
        return

    if args.report_only:
        run_report()
        return

    # ── Full pipeline ─────────────────────────────────────────────────────────
    if args.scan:
        run_scan(args.host)

    for mode in args.modes:
        run_mode(mode)

    run_parse(args.modes)

    if args.ml:
        run_ml(args.dataset)

    if args.report:
        run_report()

    log.info("Benchmark complete.")


if __name__ == "__main__":
    main()

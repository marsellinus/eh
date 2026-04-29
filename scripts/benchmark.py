#!/usr/bin/env python3
"""Menjalankan benchmark baseline, Fail2Ban, dan CrowdSec secara berurutan."""

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
BLOCK_FILE = ROOT / "logs" / "blocked_ips.txt"
FAIL2BAN_JAILS = ["sshd-docker", "nginx-http-flood"]


def sh(cmd: list[str]) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd))
    res = subprocess.run(cmd, cwd=ROOT, check=False, text=True, capture_output=True)
    if res.returncode != 0:
        if res.stdout.strip():
            print(res.stdout)
        if res.stderr.strip():
            print(res.stderr)
        raise subprocess.CalledProcessError(res.returncode, cmd, output=res.stdout, stderr=res.stderr)
    return res


def sh_optional(cmd: list[str]) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, check=False, text=True, capture_output=True)


def run_shell(script: str, *args: str):
    cmd = ["bash", script, *args]
    print("$", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def compose_cmd() -> list[str]:
    if shutil.which("docker"):
        res = sh_optional(["docker", "compose", "version"])
        if res.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        res = sh_optional(["docker-compose", "version"])
        if res.returncode == 0:
            return ["docker-compose"]
    raise RuntimeError("Docker Compose tidak ditemukan. Install docker-compose atau plugin docker compose.")


def up(mode: str):
    compose = compose_cmd()
    if mode == "baseline":
        sh([*compose, "up", "-d", "--build"])
    elif mode == "fail2ban":
        sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.fail2ban.yml", "up", "-d", "--build"])
    elif mode == "crowdsec":
        sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.crowdsec.yml", "up", "-d", "--build"])
    else:
        raise ValueError(f"Unknown mode: {mode}")


def down(mode: str):
    compose = compose_cmd()
    if mode == "baseline":
        sh([*compose, "down", "-v", "--remove-orphans"])
    elif mode == "fail2ban":
        sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.fail2ban.yml", "down", "-v", "--remove-orphans"])
    elif mode == "crowdsec":
        sh([*compose, "-f", "docker-compose.yml", "-f", "docker-compose.crowdsec.yml", "down", "-v", "--remove-orphans"])


def collect_security_snapshot(mode: str) -> dict:
    snapshot = {"mode": mode, "timestamp": time.time()}
    if mode == "fail2ban":
        res = sh(["docker", "exec", "sec-fail2ban", "fail2ban-client", "status"])
        snapshot["fail2ban_status"] = res.stdout
        snapshot["blocked_ips"] = get_fail2ban_banned_ips()
    elif mode == "crowdsec":
        res = sh(["docker", "exec", "sec-crowdsec", "cscli", "metrics"])
        snapshot["crowdsec_metrics"] = res.stdout
        snapshot["blocked_ips"] = get_crowdsec_banned_ips()
    return snapshot


def parse_fail2ban_status(output: str) -> list[str]:
    ips: list[str] = []
    for line in output.splitlines():
        if "Banned IP list" in line:
            parts = line.split(":", 1)[-1].strip()
            if parts:
                ips.extend(parts.split())
    return ips


def get_fail2ban_banned_ips() -> list[str]:
    blocked: list[str] = []
    for jail in FAIL2BAN_JAILS:
        res = sh_optional(["docker", "exec", "sec-fail2ban", "fail2ban-client", "status", jail])
        if res.returncode == 0:
            blocked.extend(parse_fail2ban_status(res.stdout))
    return sorted(set(blocked))


def get_crowdsec_banned_ips() -> list[str]:
    res = sh_optional(["docker", "exec", "sec-crowdsec", "cscli", "decisions", "list", "-o", "json"])
    if res.returncode != 0 or not res.stdout.strip():
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    blocked = [item.get("value", "").strip() for item in data if item.get("value")]
    return sorted(set(blocked))


def write_blocked_ips(mode: str) -> list[str]:
    if mode == "fail2ban":
        blocked = get_fail2ban_banned_ips()
    elif mode == "crowdsec":
        blocked = get_crowdsec_banned_ips()
    else:
        blocked = []

    lines = [f"{ip} 1;" for ip in blocked]
    BLOCK_FILE.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return blocked


def has_blocked_ips(mode: str) -> bool:
    if mode == "fail2ban":
        return len(get_fail2ban_banned_ips()) > 0
    if mode == "crowdsec":
        return len(get_crowdsec_banned_ips()) > 0
    return False


def measure_detection_time(mode: str, attack_cmd: list[str], poll_interval: float = 1.0) -> float | None:
    if mode == "baseline":
        subprocess.run(attack_cmd, cwd=ROOT, check=True)
        return None

    start = time.time()
    proc = subprocess.Popen(attack_cmd, cwd=ROOT)
    detected_at: float | None = None

    while proc.poll() is None:
        if has_blocked_ips(mode):
            detected_at = time.time()
            break
        time.sleep(poll_interval)

    proc.wait()
    if detected_at is None and has_blocked_ips(mode):
        detected_at = time.time()

    return round(detected_at - start, 2) if detected_at else None


def run_mode(mode: str):
    run_shell("scripts/reset_environment.sh")
    up(mode)
    time.sleep(12)

    metrics_proc = subprocess.Popen(["bash", "scripts/collect_metrics.sh", mode, "8", "2"], cwd=ROOT)

    http_detect = measure_detection_time(
        mode,
        [
            "bash",
            "scripts/attack_http_flood.sh",
            "http://127.0.0.1:8081/",
            "500",
            "25",
            f"results/attack_http_{mode}.log",
        ],
    )

    ssh_detect = measure_detection_time(
        mode,
        [
            "python3",
            "scripts/attack_ssh_bruteforce.py",
            "--attempts",
            "40",
            "--output",
            f"results/attack_ssh_{mode}.log",
        ],
    )

    metrics_proc.wait()

    blocked_ips = write_blocked_ips(mode)
    snapshot = collect_security_snapshot(mode)
    snapshot["detection_seconds"] = {"http": http_detect, "ssh": ssh_detect}
    snapshot["blocked_ips"] = blocked_ips
    (RESULTS / f"security_snapshot_{mode}.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    down(mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--modes", nargs="+", default=["baseline", "fail2ban", "crowdsec"])
    args = parser.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)

    for mode in args.modes:
        print(f"\\n=== Running mode: {mode} ===")
        run_mode(mode)

    print("Benchmark selesai. Lanjutkan dengan: python3 scripts/parse_results.py")


if __name__ == "__main__":
    main()

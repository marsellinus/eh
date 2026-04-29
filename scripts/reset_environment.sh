#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
	COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
	COMPOSE=(docker-compose)
else
	echo "Docker Compose tidak ditemukan. Install docker-compose atau plugin docker compose." >&2
	exit 1
fi

"${COMPOSE[@]}" down -v --remove-orphans || true
"${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.fail2ban.yml down -v --remove-orphans || true
"${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.crowdsec.yml down -v --remove-orphans || true

rm -f logs/blocked_ips.txt
: > logs/blocked_ips.txt
rm -rf logs/nginx/* logs/ssh/* logs/flask/* logs/fail2ban/* logs/crowdsec/*
mkdir -p logs/nginx logs/ssh logs/flask logs/fail2ban logs/crowdsec results

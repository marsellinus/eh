#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/run/sshd /var/log
touch /var/log/auth.log /var/log/syslog

rsyslogd
exec /usr/sbin/sshd -D -e

from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)
LOG_FILE = Path("/app/logs/access.log")
BLOCK_FILE = Path("/app/blocked_ips.txt")


def is_blocked(ip: str) -> bool:
    if not BLOCK_FILE.exists():
        return False
    lines = [line.strip() for line in BLOCK_FILE.read_text().splitlines() if line.strip()]
    return any(line.split()[0] == ip for line in lines)


@app.before_request
def log_request():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{now} {ip} {request.method} {request.path}\n")


@app.route("/")
def index():
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    if is_blocked(ip):
        return jsonify({"status": "blocked", "ip": ip}), 403
    return jsonify({"status": "ok", "service": "flask-api"})


@app.route("/health")
def health():
    return "ok\n", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

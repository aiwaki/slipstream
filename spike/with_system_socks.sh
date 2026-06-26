#!/bin/bash
# Run tlsproxy AND point the macOS system SOCKS proxy at it, so apps that ignore
# --proxy-server (notably the Discord desktop updater / Squirrel, which uses
# NSURLSession and honours the system proxy) also route through our tlsrec engine.
#
# ALWAYS restores connectivity on exit (Ctrl-C, crash, kill) so you never get
# stranded offline. Needs sudo (networksetup requires admin).
#
# Usage:
#   sudo ./with_system_socks.sh [service] [port]
#   sudo ./with_system_socks.sh "Wi-Fi" 1080
# Find your service name with:  networksetup -listallnetworkservices
set -uo pipefail

SVC="${1:-Wi-Fi}"
PORT="${2:-1080}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$HERE/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

restore() {
  echo
  echo ">> restoring: system SOCKS off on '$SVC'"
  networksetup -setsocksfirewallproxystate "$SVC" off 2>/dev/null || true
}
trap restore EXIT INT TERM

echo ">> enabling system SOCKS '$SVC' -> 127.0.0.1:$PORT"
networksetup -setsocksfirewallproxy "$SVC" 127.0.0.1 "$PORT"
networksetup -setsocksfirewallproxystate "$SVC" on

echo ">> starting tlsproxy on :$PORT  (Ctrl-C to stop AND auto-restore network)"
"$PY" "$HERE/tlsproxy.py" --port "$PORT"

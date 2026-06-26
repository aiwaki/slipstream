#!/bin/bash
# Run tlsproxy AND point the macOS system SOCKS proxy at it, so apps route through
# our tlsrec engine. Auto-detects the network service for your ACTIVE interface
# (the #1 reason a manual "Wi-Fi" guess silently does nothing).
#
# ALWAYS restores connectivity on exit (Ctrl-C, crash, kill). Needs sudo.
#
# Usage:
#   sudo ./with_system_socks.sh            # auto-detect service + port 1080
#   sudo ./with_system_socks.sh "Wi-Fi" 1080   # force a service name
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$HERE/.venv/bin/python"; [ -x "$PY" ] || PY="python3"
PORT="${2:-1080}"

# --- find the network service name for the active default-route interface ---
DEV="$(route get default 2>/dev/null | awk '/interface:/{print $2}')"
SVC="${1:-}"
if [ -z "$SVC" ]; then
  SVC="$(networksetup -listallhardwareports | awk -v d="$DEV" '
    /^Hardware Port:/{hp=$0; sub(/Hardware Port: /,"",hp)}
    /^Device:/{if($2==d){print hp; exit}}')"
fi
[ -n "$SVC" ] || SVC="Wi-Fi"

echo ">> active interface: ${DEV:-?}   network service: '$SVC'   proxy port: $PORT"

restore() {
  echo
  echo ">> restoring: system SOCKS OFF on '$SVC'"
  networksetup -setsocksfirewallproxystate "$SVC" off 2>/dev/null || true
}
trap restore EXIT INT TERM

networksetup -setsocksfirewallproxy "$SVC" 127.0.0.1 "$PORT"
networksetup -setsocksfirewallproxystate "$SVC" on
echo ">> verify (should show Enabled: Yes, 127.0.0.1:$PORT):"
networksetup -getsocksfirewallproxy "$SVC"

echo ">> starting tlsproxy --verbose on :$PORT  (Ctrl-C stops AND auto-restores)"
"$PY" "$HERE/tlsproxy.py" --port "$PORT" --verbose

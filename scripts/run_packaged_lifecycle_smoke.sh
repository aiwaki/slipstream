#!/bin/bash

set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SLIPSTREAM_DISPOSABLE_CI:-}" != "1" ]]; then
  echo "refusing Safari lifecycle smoke outside disposable GitHub Actions" >&2
  exit 2
fi

if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "usage: $0 /path/to/Slipstream.app" >&2
  exit 2
fi

app_bundle="$1"
driver_port=""
driver_url=""
driver_log="$(mktemp -t slipstream-safaridriver)"
driver_pid=""

select_driver_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

stop_driver() {
  if [[ -n "$driver_pid" ]] && kill -0 "$driver_pid" 2>/dev/null; then
    kill -TERM "$driver_pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$driver_pid" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "$driver_pid" 2>/dev/null; then
      kill -KILL "$driver_pid" 2>/dev/null || true
    fi
  fi
  if [[ -n "$driver_pid" ]]; then
    wait "$driver_pid" 2>/dev/null || true
  fi
  driver_pid=""
}

cleanup() {
  status=$?
  stop_driver
  if [[ $status -ne 0 ]]; then
    tail -n 100 "$driver_log" >&2 || true
  fi
  rm -f "$driver_log"
  exit "$status"
}
trap cleanup EXIT

start_driver() {
  local attempt driver_status exit_code
  for attempt in 1 2; do
    driver_port="$(select_driver_port)"
    driver_url="http://127.0.0.1:${driver_port}"
    printf 'SafariDriver startup attempt %s on %s\n' \
      "$attempt" "$driver_url" >>"$driver_log"
    /usr/bin/safaridriver --diagnose --port "$driver_port" \
      >>"$driver_log" 2>&1 &
    driver_pid=$!

    for _ in $(seq 1 100); do
      if ! kill -0 "$driver_pid" 2>/dev/null; then
        if wait "$driver_pid"; then
          exit_code=0
        else
          exit_code=$?
        fi
        driver_pid=""
        printf 'SafariDriver startup attempt %s exited %s\n' \
          "$attempt" "$exit_code" >>"$driver_log"
        if [[ $attempt -eq 1 ]] && /usr/bin/grep -Eq \
          'Unable to start the server: (Operation not permitted|Address already in use)' \
          "$driver_log"; then
          sleep 1
          break
        fi
        echo "SafariDriver exited during startup (attempt $attempt)" >&2
        return 1
      fi
      if driver_status="$(/usr/bin/curl --silent --show-error --noproxy '*' --max-time 2 "$driver_url/status" 2>/dev/null)"; then
        if printf '%s' "$driver_status" | python3 -c \
          'import json, sys; value = json.load(sys.stdin).get("value", {}); raise SystemExit(value.get("ready") is not True)'; then
          return 0
        fi
      fi
      sleep 0.2
    done

    if [[ -n "$driver_pid" ]]; then
      echo "SafariDriver did not become ready (attempt $attempt)" >&2
      return 1
    fi
  done
  return 1
}

sudo /usr/bin/safaridriver --enable
start_driver

sudo -E "$(command -v python3)" scripts/pf_installed_lifecycle_smoke.py \
  --app-bundle "$app_bundle" \
  --safaridriver-url "$driver_url"

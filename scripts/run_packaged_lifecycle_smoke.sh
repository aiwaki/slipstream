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
driver_port=19445
driver_url="http://127.0.0.1:${driver_port}"
driver_log="$(mktemp -t slipstream-safaridriver)"
driver_pid=""

cleanup() {
  status=$?
  if [[ -n "$driver_pid" ]] && kill -0 "$driver_pid" 2>/dev/null; then
    kill -TERM "$driver_pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$driver_pid" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "$driver_pid" 2>/dev/null; then
      kill -KILL "$driver_pid" 2>/dev/null || true
    fi
    wait "$driver_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    tail -n 100 "$driver_log" >&2 || true
  fi
  rm -f "$driver_log"
  exit "$status"
}
trap cleanup EXIT

sudo /usr/bin/safaridriver --enable
/usr/bin/safaridriver --port "$driver_port" >"$driver_log" 2>&1 &
driver_pid=$!

ready=false
for _ in $(seq 1 100); do
  if ! kill -0 "$driver_pid" 2>/dev/null; then
    echo "SafariDriver exited during startup" >&2
    exit 1
  fi
  if driver_status="$(/usr/bin/curl --silent --show-error --noproxy '*' --max-time 2 "$driver_url/status" 2>/dev/null)"; then
    if printf '%s' "$driver_status" | python3 -c \
      'import json, sys; value = json.load(sys.stdin).get("value", {}); raise SystemExit(value.get("ready") is not True)'; then
      ready=true
      break
    fi
  fi
  sleep 0.2
done

if [[ "$ready" != "true" ]]; then
  echo "SafariDriver did not become ready" >&2
  exit 1
fi

sudo -E "$(command -v python3)" scripts/pf_installed_lifecycle_smoke.py \
  --app-bundle "$app_bundle" \
  --safaridriver-url "$driver_url"

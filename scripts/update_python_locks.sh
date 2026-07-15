#!/bin/bash
set -euo pipefail

readonly root="$(cd "$(dirname "$0")/.." && pwd)"
readonly pip_tools_version="7.5.3"
python="${PYTHON:-python3}"

python_minor="$($python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$python_minor" != "3.13" ]]; then
  printf 'Python 3.13 is required to update dependency locks; found %s\n' \
    "$python_minor" >&2
  exit 1
fi

lock_env="$(mktemp -d "${TMPDIR:-/tmp}/slipstream-locks.XXXXXX")"
trap 'rm -rf "$lock_env"' EXIT

"$python" -m venv "$lock_env/venv"
"$lock_env/venv/bin/python" -m pip install \
  --quiet \
  --disable-pip-version-check \
  "pip-tools==$pip_tools_version"

cd "$root"
for lock in runtime test build; do
  input="spike/requirements-$lock.in"
  case "$lock" in
    runtime) output="spike/requirements-runtime.txt" ;;
    test) output="spike/requirements.txt" ;;
    build) output="spike/requirements-build.txt" ;;
  esac
  CUSTOM_COMPILE_COMMAND="scripts/update_python_locks.sh" \
    "$lock_env/venv/bin/pip-compile" \
      --allow-unsafe \
      --annotation-style=line \
      --generate-hashes \
      --resolver=backtracking \
      --strip-extras \
      --output-file "$output" \
      "$input"
done

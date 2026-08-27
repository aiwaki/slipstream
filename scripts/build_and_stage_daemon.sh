#!/bin/bash
# Rebuild and stage the exact current Python daemon before a Tauri bundle.
# This prevents a successful tray rebuild from silently reusing an older
# app-tauri/src-tauri/slipstreamd payload.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
python_313="${SLIPSTREAM_PYTHON_313:-}"
test_mode="${SLIPSTREAM_BUILD_STAGE_TESTING:-}"
test_failpoint="${SLIPSTREAM_BUILD_STAGE_TEST_FAILPOINT:-}"

if [[ -n "$test_failpoint" ]]; then
  if [[ "$test_mode" != "1" ]]; then
    echo "Build-stage failpoints require SLIPSTREAM_BUILD_STAGE_TESTING=1." >&2
    exit 1
  fi
  case "$test_failpoint" in
    after_backup|after_swap) ;;
    *)
      echo "Unknown build-stage test failpoint: $test_failpoint" >&2
      exit 1
      ;;
  esac
fi

fail_for_test() {
  if [[ "$test_failpoint" == "$1" ]]; then
    echo "Forced build-stage test failure: $1" >&2
    if [[ "$1" == "after_swap" ]]; then
      printf 'forced-test-corruption\n' > "$target_dir/slipstreamd"
    else
      exit 97
    fi
  fi
}

if [[ -z "$python_313" ]]; then
  python_313="$(command -v python3.13 || true)"
fi
if [[ -z "$python_313" || ! -x "$python_313" ]]; then
  echo "Python 3.13 is required; set SLIPSTREAM_PYTHON_313 to its executable." >&2
  exit 1
fi
if [[ "$("$python_313" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" != "3.13" ]]; then
  echo "SLIPSTREAM_PYTHON_313 must point to Python 3.13." >&2
  exit 1
fi

PYTHON="$python_313" "$repo_root/spike/build_daemon.sh"

source_dir="$repo_root/spike/dist/slipstreamd"
target_dir="$repo_root/app-tauri/src-tauri/slipstreamd"
stage_root="$(mktemp -d "$repo_root/app-tauri/src-tauri/.slipstreamd-stage.XXXXXX")"
stage_dir="$stage_root/slipstreamd"
backup_dir="$stage_root/previous"
stage_committed=false

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [[ "$stage_committed" != true ]]; then
    if [[ -e "$backup_dir" ]]; then
      if ! rm -rf "$target_dir" || ! mv "$backup_dir" "$target_dir"; then
        echo "Failed to restore the preceding staged daemon; backup preserved at $backup_dir" >&2
        exit 1
      fi
    elif [[ ! -e "$stage_dir" ]]; then
      if ! rm -rf "$target_dir"; then
        echo "Failed to remove the uncommitted staged daemon: $target_dir" >&2
        exit 1
      fi
    fi
  fi
  if ! rm -rf "$stage_root"; then
    echo "Failed to remove temporary daemon staging directory: $stage_root" >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

test -d "$source_dir"
test ! -L "$source_dir"
test -x "$source_dir/slipstreamd"
test ! -L "$source_dir/slipstreamd"
cp -R "$source_dir" "$stage_dir"
test -x "$stage_dir/slipstreamd"

source_sha="$(/usr/bin/shasum -a 256 "$source_dir/slipstreamd" | /usr/bin/awk '{print $1}')"
stage_sha="$(/usr/bin/shasum -a 256 "$stage_dir/slipstreamd" | /usr/bin/awk '{print $1}')"
if [[ -z "$source_sha" || "$source_sha" != "$stage_sha" ]]; then
  echo "Staged daemon does not match the freshly built daemon." >&2
  exit 1
fi

if [[ -L "$target_dir" ]]; then
  echo "Refusing to replace symlinked daemon staging directory: $target_dir" >&2
  exit 1
fi
if [[ -e "$target_dir" ]]; then
  mv "$target_dir" "$backup_dir"
fi
fail_for_test after_backup
mv "$stage_dir" "$target_dir"
fail_for_test after_swap

staged_sha="$(/usr/bin/shasum -a 256 "$target_dir/slipstreamd" | /usr/bin/awk '{print $1}')"
if [[ -z "$source_sha" || "$source_sha" != "$staged_sha" ]]; then
  echo "Staged daemon does not match the freshly built daemon." >&2
  exit 1
fi
stage_committed=true
rm -rf "$backup_dir"

echo "staged current frozen daemon: sha256:$staged_sha"

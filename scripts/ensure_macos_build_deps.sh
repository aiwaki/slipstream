#!/bin/bash
set -euo pipefail

readonly dependencies=(
  "protoc:protobuf"
  "cmake:cmake"
  "pkg-config:pkg-config"
)

missing_formulas=()
for dependency in "${dependencies[@]}"; do
  command_name="${dependency%%:*}"
  formula="${dependency#*:}"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    missing_formulas+=("$formula")
  fi
done

if (( ${#missing_formulas[@]} > 0 )); then
  brew_bin="${SLIPSTREAM_HOMEBREW_BIN:-}"
  if [[ -z "$brew_bin" ]]; then
    if ! brew_bin="$(command -v brew)"; then
      printf 'Homebrew is required to install: %s\n' "${missing_formulas[*]}" >&2
      exit 1
    fi
  fi
  if [[ ! -x "$brew_bin" ]]; then
    printf 'Homebrew executable is unavailable: %s\n' "$brew_bin" >&2
    exit 1
  fi

  printf 'Installing missing build dependencies: %s\n' "${missing_formulas[*]}"
  HOMEBREW_NO_AUTO_UPDATE=1 "$brew_bin" install "${missing_formulas[@]}"
fi

missing_commands=()
for dependency in "${dependencies[@]}"; do
  command_name="${dependency%%:*}"
  if ! command_path="$(command -v "$command_name")"; then
    missing_commands+=("$command_name")
    continue
  fi
  printf '%s -> %s\n' "$command_name" "$command_path"
done

if (( ${#missing_commands[@]} > 0 )); then
  printf 'Required build commands are still unavailable: %s\n' \
    "${missing_commands[*]}" >&2
  exit 1
fi

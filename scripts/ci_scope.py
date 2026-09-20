#!/usr/bin/env python3
"""Classify exact changed paths for the required common CI workflow."""

from __future__ import annotations

import argparse
import json
import copy
import os
import re
import subprocess
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import sys


GEPH_BOOTSTRAP_ALLOWED = frozenset(
    {
        "security/geph-dependency-audit-policy.json",
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
        "vendor/geph/VERSION",
        # Both TLS graphs may need one coordinated source-only repair. All
        # dependency audits still run; no packaged binary is promoted here.
        "app-tauri/src-tauri/Cargo.lock",
        "docs/RELEASES.md",
        "docs/DECISIONS.md",
        "docs/CURRENT_STATE.md",
        "scripts/ci_scope.py",
        "scripts/test_ci_scope.py",
        ".github/workflows/build-geph.yml",
        "scripts/test_build_config.py",
    }
)
GEPH_BOOTSTRAP_REQUIRED = frozenset(
    {
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
    }
)
WINDOWS_PREFIXES = (
    "contracts/",
    "crates/slipstream-core/",
    "crates/slipstream-userspace-stack-evaluation/",
    "crates/slipstream-userspace-stack-effect-evaluation/",
    "crates/slipstream-windows-adapter/",
    "vendor/wintun/",
)
WINDOWS_EXACT = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/windows-packet-adapter-qualification.yml",
    }
)


@dataclass(frozen=True)
class CiScope:
    geph_bootstrap: bool
    product: bool
    windows: bool


def _validate_path(raw: str) -> str:
    if "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError("changed path contains a forbidden control character")
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise ValueError(f"invalid repository-relative changed path: {raw!r}")
    return raw


def _is_documentation(path: str) -> bool:
    return (
        path in {"README.md", "README.en.md"}
        or path.startswith("docs/")
        or path.endswith(".md")
    )


APP_LOCK = "app-tauri/src-tauri/Cargo.lock"
# Reviewed RUSTSEC-2026-0285 migration only. This is not a blanket lockfile
# exemption: any other dependency, checksum, dependency edge or metadata change
# must take the ordinary packaged-build path.
APP_LOCK_REPAIRS = (
    ("rustls", "0.23.41", "6b92b125634d9b795e7beca796cc790df15a7fb38323bf3196fda83292d06b1f",
     "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634"),
    ("rustls-webpki", "0.103.13", "61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e",
     "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2"),
)


def reviewed_app_lock_repair(before: str, after: str) -> bool:
    try:
        original, actual = tomllib.loads(before), tomllib.loads(after)
        expected = copy.deepcopy(original)
        for name, old, old_hash, new, new_hash in APP_LOCK_REPAIRS:
            matches = [p for p in expected["package"] if p["name"] == name and p["version"] == old]
            if len(matches) != 1:
                return False
            package = matches[0]
            if package.get("checksum") != old_hash or package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                return False
            package.update(version=new, checksum=new_hash)
        return actual == expected
    except (ValueError, KeyError, TypeError):
        return False


def app_lock_delta_from_git() -> tuple[str, str] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return tuple(subprocess.check_output(
            ["git", "show", f"{ref}:{APP_LOCK}"], text=True, stderr=subprocess.DEVNULL,
            timeout=10) for ref in refs)
    except (OSError, subprocess.SubprocessError):
        return None


def classify_paths(paths: list[str], *, event_name: str,
                   app_lock_delta: tuple[str, str] | None = None) -> CiScope:
    if event_name not in {"pull_request", "push"}:
        raise ValueError(f"unsupported CI event: {event_name}")
    changed = {_validate_path(path) for path in paths if path}
    if not changed:
        return CiScope(geph_bootstrap=False, product=True, windows=True)
    product = any(not _is_documentation(path) for path in changed)
    windows = any(
        path in WINDOWS_EXACT or path.startswith(WINDOWS_PREFIXES)
        for path in changed
    )
    geph_bootstrap = (
        event_name == "pull_request"
        and GEPH_BOOTSTRAP_REQUIRED.issubset(changed)
        and changed.issubset(GEPH_BOOTSTRAP_ALLOWED)
        and (APP_LOCK not in changed or (
            app_lock_delta is not None and reviewed_app_lock_repair(*app_lock_delta)))
        and ("scripts/ci_scope.py" not in changed or "scripts/test_ci_scope.py" in changed)
        and (".github/workflows/build-geph.yml" not in changed or "scripts/test_build_config.py" in changed)
    )
    return CiScope(
        geph_bootstrap=geph_bootstrap,
        product=product,
        windows=windows,
    )


def write_github_output(path: Path, scope: CiScope) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(f"geph_bootstrap={str(scope.geph_bootstrap).lower()}\n")
        output.write(f"product={str(scope.product).lower()}\n")
        output.write(f"windows={str(scope.windows).lower()}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", choices=("pull_request", "push"), required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = [line.rstrip("\n") for line in sys.stdin]
    delta = app_lock_delta_from_git() if args.event_name == "pull_request" and APP_LOCK in paths else None
    scope = classify_paths(paths, event_name=args.event_name, app_lock_delta=delta)
    write_github_output(args.github_output, scope)
    print(json.dumps(asdict(scope), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

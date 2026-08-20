#!/usr/bin/env python3
"""Classify exact changed paths for the required common CI workflow."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import sys


GEPH_BOOTSTRAP_ALLOWED = frozenset(
    {
        "security/geph-dependency-audit-policy.json",
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
        "vendor/geph/VERSION",
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


def classify_paths(paths: list[str], *, event_name: str) -> CiScope:
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
    scope = classify_paths(
        [line.rstrip("\n") for line in sys.stdin], event_name=args.event_name
    )
    write_github_output(args.github_output, scope)
    print(json.dumps(asdict(scope), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

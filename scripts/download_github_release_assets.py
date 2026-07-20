#!/usr/bin/env python3
"""Download an immutable GitHub release asset set with bounded retries."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from fnmatch import fnmatchcase
from pathlib import Path


DEFAULT_ATTEMPTS = 4
DEFAULT_DELAY_SECONDS = 2.0


def download_release_assets(
    *,
    repository: str,
    tag: str,
    output: Path,
    patterns: Sequence[str],
    attempts: int = DEFAULT_ATTEMPTS,
    delay_seconds: float = DEFAULT_DELAY_SECONDS,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    if not repository or not tag or not patterns:
        raise ValueError("repository, tag, and at least one pattern are required")
    if attempts < 1 or delay_seconds < 0:
        raise ValueError("retry bounds are invalid")
    if output.exists() or output.is_symlink():
        raise ValueError("output path must not already exist")

    output.parent.mkdir(parents=True, exist_ok=True)
    last_detail = "release download failed"
    for attempt in range(1, attempts + 1):
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.download.", dir=output.parent)
        )
        command = ["gh", "release", "download", tag, "--repo", repository]
        for pattern in patterns:
            command.extend(("--pattern", pattern))
        command.extend(("--dir", str(temporary)))
        try:
            completed = runner(command, capture_output=True, text=True, check=False)
            downloaded = tuple(path.name for path in temporary.iterdir() if path.is_file())
            missing = tuple(
                pattern
                for pattern in patterns
                if not any(fnmatchcase(name, pattern) for name in downloaded)
            )
            if completed.returncode == 0 and downloaded and not missing:
                temporary.replace(output)
                return
            detail = (completed.stderr or completed.stdout or "").strip()
            if completed.returncode != 0:
                last_detail = detail or f"release download exited {completed.returncode}"
            elif missing:
                last_detail = "release download omitted: " + ", ".join(missing)
            else:
                last_detail = detail or "release download returned no assets"
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

        if attempt < attempts:
            print(
                f"release download attempt {attempt}/{attempts} failed: {last_detail}",
                file=sys.stderr,
            )
            sleeper(delay_seconds * attempt)

    raise RuntimeError(
        f"release download failed after {attempts} attempts: {last_detail}"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pattern", required=True, action="append")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--delay-seconds", type=float, default=DEFAULT_DELAY_SECONDS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    download_release_assets(
        repository=args.repo,
        tag=args.tag,
        output=args.output,
        patterns=args.pattern,
        attempts=args.attempts,
        delay_seconds=args.delay_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

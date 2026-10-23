#!/usr/bin/env python3
"""Classify exact changed paths for the required common CI workflow."""

from __future__ import annotations

import argparse
import hashlib
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
        "vendor/geph/README.md",
        "scripts/geph_vendor_source.py",
        "scripts/test_geph_source_edits.py",
        "scripts/test_geph_embedded_source.py",
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
        "scripts/run_geph_synthetic_tests.py",
        "scripts/test_run_geph_synthetic_tests.py",
        "docs/ROUTING_RESEARCH.md",
    }
)
GEPH_BOOTSTRAP_REQUIRED = frozenset(
    {
        "vendor/geph/Cargo.lock",
        "vendor/geph/SOURCE.json",
    }
)
# One coordinated delivery repair. Exact file bytes keep this from becoming a
# general app/policy exemption. Full packaged checks still run on main, after
# its producer publishes the reviewed Geph dependency; both audits run on PRs.
DELIVERY_FILE_BINDINGS = {
    '.github/workflows/dependency-audit.yml': (
        '712ded84e3de62029067b6c3549829b3ed62e3a19b510a25cee842f684313285',
        '709049d4b60b63a2e1d3d1150028457af1ea28c0627dc4b26c069f24fe9bb29f'),
    'vendor/chromium-headless-shell/SOURCE.json': (
        'bec2143e32afe1dfc128baff9183001451e3814c942140e782519d4363f49629',
        '91a914cb43c5f8a6be8d3dc2da1ca4a05c963f95938a5c4bb0ab9cd5bbf05618'),
    'app-tauri/src-tauri/src/browser_probe.rs': (
        '20ccd41ac021c5308a70eeeca70779e93a629dbb3069185ac1a87bcb52df54cb',
        '3d2b36ac1047fbc3f9cf25cc6ede2a69f104bcdeafa60371ab38177463839882'),
    'security/dependency-audit-policy.json': (
        'a3e663bdc2d5a999b9454f6cb95d35711240793d337acc3e3a7b1b32892efb16',
        'dbcab882c56bd7daec4cdc8d964f95a84359cf83c66050497cae081b01009bdd'),
    'scripts/dependency_audit.py': (
        'a73162775fe9a47f00dc302e4d91ff9d828b7e54e17aef1a96603d8f87b246eb',
        'e40869f5329103af2b595f001bfe0b9941c25422b284fa4f6b49a7ad444d4cf9'),
}
DELIVERY_TEST_PATHS = frozenset({
    "scripts/test_build_config.py",
    "scripts/test_dependency_audit.py",
    "scripts/test_materialize_chromium_headless_shell.py",
    "scripts/test_make_release_manifest.py",
    "scripts/test_verify_release_artifacts.py",
})
# Coordinate the emSign trust-store repair with the Geph producer. Every Python
# lock must carry this exact certifi-only update; installer options, unrelated
# dependencies and a partial runtime/test/build update take ordinary packaging.
PYTHON_LOCK_FILE_BINDINGS = {
    "spike/requirements-runtime.txt": (
        "dbc2159711423ff43b87f697c62ae482869bcbe8ec7b697089606a70b910f828",
        "540a6aae9d82fca17647fa052eb772ffb8e1d77b7c4f53c0513a3cca42a7fe74"),
    "spike/requirements.txt": (
        "986abfc91327d355981a05184e7b7b2f5fe6f576a84338c19c021f6bb72a5cda",
        "2c79f2c8c826eb2203dea9b765283f57b1bab894112cc65e7a4309867435a975"),
    "spike/requirements-build.txt": (
        "1192b9d29eb533db2bf29733ee494448d8c12c38a8b9c49f1e06fbda424078f9",
        "a740216126da538358eb8009447d6afc64d70819390a9c82d207be727a36179d"),
}
GEPH_BOOTSTRAP_ALLOWED = (GEPH_BOOTSTRAP_ALLOWED | DELIVERY_FILE_BINDINGS.keys()
                          | DELIVERY_TEST_PATHS | PYTHON_LOCK_FILE_BINDINGS.keys())


def reviewed_delivery_delta(deltas: dict[str, tuple[bytes, bytes]] | None) -> bool:
    if deltas is None or deltas.keys() != DELIVERY_FILE_BINDINGS.keys():
        return False
    try:
        return all(
            tuple(hashlib.sha256(value).hexdigest() for value in deltas[path]) == binding
            for path, binding in DELIVERY_FILE_BINDINGS.items()
        )
    except (TypeError, ValueError):
        return False


def delivery_delta_from_git() -> dict[str, tuple[bytes, bytes]] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return {
            path: tuple(subprocess.check_output(
                ["git", "show", f"{ref}:{path}"], stderr=subprocess.DEVNULL,
                timeout=10) for ref in refs)
            for path in DELIVERY_FILE_BINDINGS
        }
    except (OSError, subprocess.SubprocessError):
        return None


def reviewed_python_lock_delta(deltas: dict[str, tuple[bytes, bytes]] | None) -> bool:
    if deltas is None or deltas.keys() != PYTHON_LOCK_FILE_BINDINGS.keys():
        return False
    try:
        return all(
            tuple(hashlib.sha256(value).hexdigest() for value in deltas[path]) == binding
            for path, binding in PYTHON_LOCK_FILE_BINDINGS.items()
        )
    except (TypeError, ValueError):
        return False


def python_lock_delta_from_git() -> dict[str, tuple[bytes, bytes]] | None:
    refs = (os.environ.get("BASE_SHA", ""), os.environ.get("GITHUB_SHA", ""))
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs):
        return None
    try:
        return {
            path: tuple(subprocess.check_output(
                ["git", "show", f"{ref}:{path}"], stderr=subprocess.DEVNULL,
                timeout=10) for ref in refs)
            for path in PYTHON_LOCK_FILE_BINDINGS
        }
    except (OSError, subprocess.SubprocessError):
        return None


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
# Reviewed TLS migrations only. This is not a blanket lockfile
# exemption: any other dependency, checksum, dependency edge or metadata change
# must take the ordinary packaged-build path.
APP_LOCK_REPAIRS = (
    ("rustls", "0.23.41", "6b92b125634d9b795e7beca796cc790df15a7fb38323bf3196fda83292d06b1f",
     "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634"),
    ("rustls-webpki", "0.103.13", "61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e",
     "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2"),
)
APP_LOCK_REPAIR_SETS = (
    APP_LOCK_REPAIRS,
    # RUSTSEC-2026-0346/0347/0348/0349. The previous migration is already on
    # main; recognize this exact subsequent repair without admitting other
    # lockfile changes into source bootstrap.
    (("rustls", "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
      "0.23.46", "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"),),
    # The same delivery graph also repairs the five current QUIC advisories.
    # Version/checksum pairs only; dependency edges and all other bytes of the
    # parsed lock contract must still be unchanged.
    (
        ("rustls", "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
         "0.23.46", "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"),
        ("quinn-proto", "0.11.16", "2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560",
         "0.11.18", "a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc"),
    ),
    # RUSTSEC-2026-0382/0381: certificate-validation and emSign root repair.
    # Both version/checksum changes are required, with every edge preserved.
    (
        ("rustls-webpki", "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2",
         "0.103.16", "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281"),
        ("webpki-roots", "1.0.9", "7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a",
         "1.0.10", "1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9"),
    ),
)


def reviewed_app_lock_repair(before: str, after: str) -> bool:
    try:
        original, actual = tomllib.loads(before), tomllib.loads(after)
        for repairs in APP_LOCK_REPAIR_SETS:
            expected = copy.deepcopy(original)
            for name, old, old_hash, new, new_hash in repairs:
                matches = [p for p in expected["package"] if p["name"] == name and p["version"] == old]
                if len(matches) != 1:
                    break
                package = matches[0]
                if package.get("checksum") != old_hash or package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                    break
                if any(p["name"] == name and p["version"] == new
                       and p.get("source") == package["source"] for p in expected["package"]):
                    break
                package.update(version=new, checksum=new_hash)
            else:
                if actual == expected:
                    return True
        return False
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
                   app_lock_delta: tuple[str, str] | None = None,
                   delivery_delta: dict[str, tuple[bytes, bytes]] | None = None,
                   python_lock_delta: dict[str, tuple[bytes, bytes]] | None = None) -> CiScope:
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
        and (GEPH_BOOTSTRAP_REQUIRED.issubset(changed) or {
            "vendor/geph/SOURCE.json", "scripts/geph_vendor_source.py",
            "scripts/test_geph_source_edits.py",
        }.issubset(changed) or (
            # Existing guarded source edits may change without a lock update.
            # verify-transition still validates the exact contract/revision;
            # binary and application changes cannot enter this path.
            "vendor/geph/SOURCE.json" in changed
            and changed.issubset({
                "vendor/geph/SOURCE.json", "vendor/geph/README.md", "docs/CURRENT_STATE.md",
                "docs/DECISIONS.md", "scripts/ci_scope.py",
                "scripts/test_ci_scope.py",
            })
        ))
        and changed.issubset(GEPH_BOOTSTRAP_ALLOWED)
        and (not (changed & DELIVERY_FILE_BINDINGS.keys()) or (
            (DELIVERY_FILE_BINDINGS.keys() | DELIVERY_TEST_PATHS | GEPH_BOOTSTRAP_REQUIRED).issubset(changed)
            and reviewed_delivery_delta(delivery_delta)))
        and (not (changed & PYTHON_LOCK_FILE_BINDINGS.keys()) or (
            (PYTHON_LOCK_FILE_BINDINGS.keys() | GEPH_BOOTSTRAP_REQUIRED).issubset(changed)
            and reviewed_python_lock_delta(python_lock_delta)))
        and ("scripts/run_geph_synthetic_tests.py" not in changed or "scripts/test_run_geph_synthetic_tests.py" in changed)
        and ("scripts/geph_vendor_source.py" not in changed or "scripts/test_geph_source_edits.py" in changed)
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
    delivery_delta = (delivery_delta_from_git()
        if args.event_name == "pull_request" and set(paths) & DELIVERY_FILE_BINDINGS.keys() else None)
    python_lock_delta = (python_lock_delta_from_git()
        if args.event_name == "pull_request" and set(paths) & PYTHON_LOCK_FILE_BINDINGS.keys() else None)
    scope = classify_paths(paths, event_name=args.event_name, app_lock_delta=delta,
                           delivery_delta=delivery_delta, python_lock_delta=python_lock_delta)
    write_github_output(args.github_output, scope)
    print(json.dumps(asdict(scope), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

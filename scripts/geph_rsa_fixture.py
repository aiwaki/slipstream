"""Materialize a hash-bound, test-only copy of the current Geph RSA client."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import stat

FIXTURES = Path(__file__).resolve().parent / "fixtures/geph-rsa-auth"
RSA_TESTS = tuple("rsa_composition_tests::" + name for name in (
    "actual_auth_and_bandwidth_futures_are_send",
    "auth_current_next_epoch_configured_root_and_exact_legacy_sqlite_roundtrip",
    "auth_wrong_level_uses_fresh_blind_and_request_selected_free_root",
    "auth_wrong_epoch_root_key_signature_and_oversize_never_publish",
    "auth_no_root_mode_remains_explicit_but_still_requires_pending_key",
    "auth_cancellation_at_signing_rpc_does_not_submit_cache_write",
    "bandwidth_real_spawned_futures_publish_and_consume_legacy_cache",
    "bandwidth_cancellation_at_auth_and_signing_await_drains_mock_calls",
    "sqlite_cancellation_before_acquire_and_after_commit_are_different",
    "auth_actual_thirty_second_timeout_drops_pending_before_publication",
    "bandwidth_configured_key_mismatch_retries_without_publication",
))
APPENDS = {
    "src/auth.rs": '\n#[cfg(test)]\npub(crate) async fn composition_refresh(ctx: &AnyCtx<Config>, token: &str) -> anyhow::Result<()> {\n    refresh_conn_token(ctx, token).await\n}\n',
    "src/bw_token.rs": '\n#[cfg(test)]\npub(crate) async fn composition_refresh(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {\n    bw_token_refresh_inner(ctx).await\n}\n',
    "src/lib.rs": '\n#[cfg(test)]\nmod rsa_composition_tests;\n',
}
BROKER_ANCHOR = "pub fn broker_client(ctx: &AnyCtx<Config>) -> anyhow::Result<&BrokerClient> {\n"
BROKER_HOOK = ('    #[cfg(test)]\n'
               '    if let Some(client) = ctx.get(crate::rsa_composition_tests::SYNTHETIC_BROKER).as_ref() { return Ok(client); }\n')


def _read(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
        raise ValueError(f"non-regular or oversized RSA fixture input: {path.name}")
    return path.read_bytes()


def snapshot(root: Path) -> dict[str, str]:
    """Reject links, special entries and unbounded input trees before copying."""
    result = {}
    total = 0
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        data = _read(path)
        total += len(data)
        if total > 16 * 1024 * 1024:
            raise ValueError("RSA fixture input tree exceeds its byte bound")
        result[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
        if len(result) > 512:
            raise ValueError("RSA fixture input tree exceeds its file bound")
    return result


def assert_unchanged(source: Path, expected: dict[str, str]) -> None:
    if snapshot(source) != expected:
        raise ValueError("production Geph input tree changed during synthetic qualification")


def prepare(source: Path, contract: Path, root: Path, *, fixtures: Path = FIXTURES) -> dict:
    """Copy current inputs; never copy an older implementation or resolve a lock."""
    catalog_bytes = _read(fixtures / "closure.json")
    catalog = json.loads(catalog_bytes)
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise ValueError("invalid RSA fixture closure schema")
    source_bytes = _read(contract)
    if hashlib.sha256(source_bytes).hexdigest() != catalog.get("source_sha256"):
        raise ValueError("RSA fixture catalog does not bind current SOURCE")
    description = json.loads(source_bytes)
    if "native_sqlite" in description or not description.get("embedded_packages"):
        raise ValueError("RSA fixture requires the reviewed source-owned SQLx client")
    if hashlib.sha256(_read(source / "Cargo.lock")).hexdigest() != catalog.get("lock_sha256"):
        raise ValueError("RSA fixture catalog does not bind current lock")
    production = snapshot(source)
    if production != catalog.get("production_files"):
        raise ValueError("materialized production bytes differ from reviewed RSA fixture inputs")
    available = snapshot(fixtures)
    selected = {name: value for name, value in available.items() if name not in {"closure.json", "README.md"}}
    if selected != catalog.get("fixture_files") or len(selected) != 9:
        raise ValueError("RSA fixture closure is missing, altered or contains extra files")
    text = _read(fixtures / "rsa_composition_tests.rs").decode()
    names = re.findall(r"#\[(?:test|tokio::test)\]\s*(?:async\s+)?fn\s+(\w+)", text)
    if tuple("rsa_composition_tests::" + name for name in names) != RSA_TESTS:
        raise ValueError("RSA fixture exact-case allowlist differs from retained source")
    root.mkdir(parents=True, exist_ok=False)
    for name in selected:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixtures / name, target)
        if hashlib.sha256(_read(target)).hexdigest() != selected[name]:
            raise ValueError("RSA fixture changed while copying")
    copy = root / "composition/geph5-client"
    shutil.copytree(source, copy)
    assert_unchanged(copy, production)
    expected_copy = dict(production)
    for name, addition in APPENDS.items():
        path = copy / name
        data = _read(path) + addition.encode()
        path.write_bytes(data)
        expected_copy[name] = hashlib.sha256(data).hexdigest()
    path = copy / "src/broker.rs"
    text = _read(path).decode()
    if text.count(BROKER_ANCHOR) != 1:
        raise ValueError("broker test hook requires exactly one reviewed insertion site")
    data = text.replace(BROKER_ANCHOR, BROKER_ANCHOR + BROKER_HOOK, 1).encode()
    path.write_bytes(data)
    expected_copy["src/broker.rs"] = hashlib.sha256(data).hexdigest()
    fixture = root / "rsa_composition_tests.rs"
    shutil.copyfile(fixture, copy / "src/rsa_composition_tests.rs")
    expected_copy["src/rsa_composition_tests.rs"] = selected["rsa_composition_tests.rs"]
    assert_unchanged(copy, expected_copy)
    assert_unchanged(source, production)
    (root / "composition/tmp").mkdir()
    return {"source": copy, "oracle": root / "legacy-oracle", "root": root,
            "production_files": production, "test_files": expected_copy,
            "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
            "fixture_files": selected}

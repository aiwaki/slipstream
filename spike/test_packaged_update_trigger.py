"""Hermetic trigger-builder checks: no compiler, daemon, sudo, or network."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_packaged_update_trigger as trigger
from native_root_update import Refused


def pair():
    return {"schema_version": 1,
            "old": {"source_commit": "a" * 40, "candidate_manifest_sha256": "b" * 64, "run_id": 10, "run_attempt": 2},
            "new": {"source_commit": "c" * 40, "candidate_manifest_sha256": "d" * 64, "run_id": 11, "run_attempt": 1}}


def test_pair_preserves_exact_source_manifest_and_successful_attempt():
    value = pair()
    assert trigger.pins(value) == value
    assert value["old"]["run_attempt"] == 2


@pytest.mark.parametrize("key,value", [("source_commit", "main"), ("candidate_manifest_sha256", "short"),
                                        ("run_id", True), ("run_attempt", 0), ("run_id", 11)])
def test_ambiguous_pair_is_rejected(key, value):
    pins = pair()
    pins["old"][key] = value
    with pytest.raises(Refused):
        trigger.pins(pins)


def test_generated_manifest_keeps_exact_old_lock_graph_without_product_targets(tmp_path):
    source = (ROOT / "app-tauri/src-tauri/Cargo.toml").read_text()
    old = tomllib.loads(source)
    generated = tomllib.loads(trigger.crate_manifest(source, tmp_path))
    assert generated["package"] == {**old["package"], "build": False, "autobins": False}
    assert generated["bin"] == [{"name": trigger.BIN, "path": "bridge.rs"}]
    assert "lib" not in generated
    expected = copy.deepcopy(old)
    expected["dependencies"]["slipstream-core"]["path"] = str(tmp_path / "crates/slipstream-core")
    for name in ("dependencies", "build-dependencies", "dev-dependencies", "target", "profile"):
        assert generated[name] == expected[name]


def test_unexpected_old_manifest_shape_fails_closed(tmp_path):
    source = (ROOT / "app-tauri/src-tauri/Cargo.toml").read_text()
    for modified in (source.replace("[package]", "[package]\nbuild = 'other.rs'"),
                     source.replace('../../crates/slipstream-core', '../unreviewed-core')):
        with pytest.raises(Refused):
            trigger.crate_manifest(modified, tmp_path)


def test_bridge_uses_old_modules_and_key_not_current_app_library(tmp_path):
    old = tmp_path / "exact-old"
    source = trigger.bridge_source(old, tmp_path / "trigger.rs", tmp_path / "plan.json", "OLD-KEY")
    for name in ("app_update", "install_attestation", "updater_transaction"):
        assert json.dumps(str(old / "app-tauri/src-tauri/src" / (name + ".rs"))) in source
    assert 'const OLD_PUBLIC_KEY: &str = "OLD-KEY";' in source
    assert "slipstream_lib" not in source
    assert "fn main() { trigger::main(); }" in source


def source_fixture(tmp_path, monkeypatch):
    paths = ["app-tauri/src-tauri/src/" + n + ".rs" for n in trigger.MODULES]
    paths += ["app-tauri/src-tauri/" + n for n in ("Cargo.toml", "Cargo.lock", "tauri.conf.json")]
    paths += ["crates/slipstream-core/src/lib.rs", "contracts/update-bundle-tree-v1.json"]
    contents = {p: ("exact source: " + p).encode() for p in paths}
    for p, content in contents.items():
        file = tmp_path / p
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)

    def git(old, *args):
        assert old == tmp_path
        if args == ("rev-parse", "HEAD"):
            return b"a" * 40 + b"\n"
        if args == ("rev-parse", "HEAD^{tree}"):
            return b"b" * 40 + b"\n"
        if args[0] == "status":
            return b""
        if args[0] == "ls-files":
            return "\n".join(paths[-2:]).encode()
        assert args[0] == "show"
        return contents[args[1].removeprefix("HEAD:")]

    monkeypatch.setattr(trigger, "git", git)
    return contents, {"source": {"commit": "a" * 40, "tree": "b" * 40}}


def test_source_receipt_binds_actual_module_core_and_contract_bytes(tmp_path, monkeypatch):
    contents, manifest = source_fixture(tmp_path, monkeypatch)
    hashes = trigger.verified_source(tmp_path, manifest)
    assert hashes == {p: hashlib.sha256(b).hexdigest() for p, b in contents.items()}
    (tmp_path / "app-tauri/src-tauri/src/updater_transaction.rs").write_text("changed")
    with pytest.raises(Refused, match="source bytes changed"):
        trigger.verified_source(tmp_path, manifest)


def test_source_commit_must_match_authenticated_old_candidate(tmp_path, monkeypatch):
    _, manifest = source_fixture(tmp_path, monkeypatch)
    manifest["source"]["commit"] = "c" * 40
    with pytest.raises(Refused, match="SHA mismatch"):
        trigger.verified_source(tmp_path, manifest)


def test_crate_creation_does_not_overwrite_prior_run_or_old_inputs(tmp_path):
    old = tmp_path / "old"
    cargo = old / "app-tauri/src-tauri"
    cargo.mkdir(parents=True)
    source = (ROOT / "app-tauri/src-tauri/Cargo.toml").read_text()
    (cargo / "Cargo.toml").write_text(source)
    (cargo / "Cargo.lock").write_bytes(b"# exact OLD lock\n")
    output = tmp_path / "generated"
    trigger.write_crate(output, old, tmp_path / "trigger.rs", {"test": True}, "OLD-KEY")
    assert (output / "Cargo.lock").read_bytes() == (cargo / "Cargo.lock").read_bytes()
    assert (cargo / "Cargo.toml").read_text() == source
    assert sorted(p.name for p in output.iterdir()) == ["Cargo.lock", "Cargo.toml", "bridge.rs", "pinned-plan.json"]
    with pytest.raises(FileExistsError):
        trigger.write_crate(output, old, tmp_path / "trigger.rs", {}, "OTHER-KEY")
    assert json.loads((output / "pinned-plan.json").read_text()) == {"test": True}

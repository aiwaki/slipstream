#!/usr/bin/env python3
"""Materialize a non-shipping qualification driver with the exact .23 preparer.

Only writes build inputs. Does not run an updater or change an installed app.
The generated entry point retains every disposable-runner guard from the current
qualification driver; only its transaction module is replaced by pinned source.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SOURCE = "6ba71ef75d821ee74cedcee5d8a9c83495da7c76"
SOURCE_PATH = "app-tauri/src-tauri/src/updater_transaction.rs"
SOURCE_SHA256 = "ab48e76daebc26b9238fc8c3beaf51dcf5b7ae6f1509dd71dfa8d15d6b3c9a4e"
MODULE = '#[path = "../src/updater_transaction.rs"]'


def materialize(repo: Path, source: bytes) -> dict:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("published .23 preparer digest mismatch")
    examples = repo / "app-tauri/src-tauri/examples"
    entry = (examples / "prepare_packaged_update.rs").read_text()
    if entry.count(MODULE) != 1:
        raise ValueError("qualification entry point module binding changed")
    selection = """let prepare = if migration {
        updater_transaction::prepare_legacy_migration_transaction
    } else {
        updater_transaction::prepare_transaction
    };"""
    if selection in entry:
        entry = entry.replace(selection, """if migration {
        return Err("historical driver cannot prepare an external migration".into());
    }
    let prepare = updater_transaction::prepare_transaction;""")
    start = entry.find("    // BEGIN_RUNNING_MIGRATION")
    if start >= 0:
        end_marker = "    // END_RUNNING_MIGRATION"
        end = entry.index(end_marker, start) + len(end_marker)
        entry = entry[:start] + '    let _ = running_pid;\n' + entry[end:]
    generated = examples / "legacy23_generated"
    driver = examples / "prepare_legacy23_update.rs"
    if driver.exists() or driver.is_symlink():
        raise FileExistsError(f"generated driver already exists: {driver}")
    # Refuse reuse: stale or edited generated sources must never silently become
    # evidence for a new legacy run. The caller owns removal after inspection.
    generated.mkdir(mode=0o700)
    module = generated / "updater_transaction.rs"
    module.write_bytes(source)
    with driver.open("x") as stream:
        stream.write(entry.replace(MODULE,
                     '#[path = "legacy23_generated/updater_transaction.rs"]'))
    report = {
        "source_commit": SOURCE, "source_path": SOURCE_PATH,
        "source_sha256": SOURCE_SHA256,
        "entry_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
        "coverage": "pinned-legacy-preparer-build-inputs-not-runtime-qualification",
    }
    (generated / "provenance.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    source = subprocess.run(["git", "show", f"{SOURCE}:{SOURCE_PATH}"],
                            cwd=repo, capture_output=True, check=True).stdout
    print(json.dumps(materialize(repo, source), indent=2))


if __name__ == "__main__":
    main()

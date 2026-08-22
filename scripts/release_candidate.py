#!/usr/bin/env python3
"""Create and verify immutable Slipstream release-candidate contracts.

The candidate is built once by the required main CI lifecycle.  Protected
qualification and the publisher consume the exact same binary files.  The
manifest deliberately excludes tag-specific metadata (the updater index and
public release manifest), which the publisher may create without rebuilding
the application.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

import dependency_audit
import make_release_manifest
import make_release_sbom


SCHEMA_VERSION = 1
MANIFEST_NAME = "release-candidate-manifest.json"
PROOF_NAME = "release-qualification.json"
SBOM_NAME = make_release_manifest.SBOM_NAME
AUDIT_NAME = make_release_manifest.DEPENDENCY_AUDIT_NAME
BUILD_WORKFLOW = ".github/workflows/ci.yml"
QUALIFICATION_WORKFLOW = ".github/workflows/owned-geph-qualification.yml"
READINESS_QUALIFICATION_WORKFLOW = ".github/workflows/release-readiness.yml"
QUALIFICATION_WORKFLOWS = frozenset(
    (QUALIFICATION_WORKFLOW, READINESS_QUALIFICATION_WORKFLOW)
)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT = re.compile(r"[0-9a-f]{40,64}")
REQUIRED_FILES = {
    "Slipstream-macos-arm64.zip",
    "Slipstream.app.tar.gz",
    "Slipstream.app.tar.gz.sig",
    SBOM_NAME,
    AUDIT_NAME,
}


def _read_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, value: dict) -> None:
    make_release_sbom.write_json_atomic(path, value)


def _candidate_tag(source_commit: str) -> str:
    return f"release-candidate-{source_commit}"


def _validate_identity(
    *,
    repository: str,
    version: str,
    source_commit: str,
    source_tree: str,
    source_archive_sha256: str,
    source_date_epoch: int,
    target: str,
) -> None:
    if not isinstance(
        repository, str
    ) or not make_release_sbom.REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    if not isinstance(
        source_commit, str
    ) or not make_release_sbom.SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if not isinstance(source_tree, str) or not GIT_OBJECT.fullmatch(source_tree):
        raise ValueError("source tree must be a full lowercase Git object ID")
    if not isinstance(
        source_archive_sha256, str
    ) or not HEX_SHA256.fullmatch(source_archive_sha256):
        raise ValueError("source archive SHA-256 is invalid")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("version is required")
    if (
        not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 0
    ):
        raise ValueError("source date epoch must be non-negative")
    if not isinstance(target, str) or target not in make_release_manifest.TARGETS:
        raise ValueError(f"unsupported release target: {target}")


def _artifact_kind(name: str) -> str:
    if name == "Slipstream-macos-arm64.zip":
        return "first-install"
    if name == "Slipstream.app.tar.gz":
        return "updater-archive"
    if name == "Slipstream.app.tar.gz.sig":
        return "updater-signature"
    if name == SBOM_NAME:
        return "candidate-sbom"
    if name == AUDIT_NAME:
        return "candidate-dependency-audit"
    if name.startswith("Slipstream_") and name.endswith(".dmg"):
        return "disk-image"
    raise ValueError(f"unexpected release-candidate artifact: {name}")


def deterministic_tree_sha256(root: Path) -> str:
    """Hash the complete unpacked app tree without trusting ZIP metadata."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError("candidate app tree is missing or unsafe")
    digest = hashlib.sha256()
    root_mode = f"{stat.S_IMODE(root.lstat().st_mode):o}".encode()
    for field in (b"directory", b".", root_mode, b""):
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            kind = b"symlink"
            payload = os.readlink(path).encode("utf-8")
        elif path.is_dir():
            kind = b"directory"
            payload = b""
        elif path.is_file():
            kind = b"file"
            file_digest, _ = make_release_manifest.hash_regular_file(
                path, allow_empty=True
            )
            payload = bytes.fromhex(file_digest)
        else:
            raise ValueError(f"unsupported candidate app tree entry: {relative}")
        for field in (kind, relative.encode("utf-8"), f"{mode:o}".encode(), payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def collect_candidate_artifacts(candidate_dir: Path) -> list[dict]:
    if not candidate_dir.is_dir():
        raise ValueError(f"candidate directory does not exist: {candidate_dir}")
    artifacts: list[dict] = []
    for path in sorted(candidate_dir.iterdir(), key=lambda item: item.name):
        if path.name in {MANIFEST_NAME, PROOF_NAME}:
            continue
        if path.is_symlink():
            raise ValueError(f"candidate artifact must not be a symlink: {path.name}")
        sha256, size = make_release_manifest.hash_regular_file(path)
        artifacts.append(
            {
                "name": path.name,
                "kind": _artifact_kind(path.name),
                "sha256": sha256,
                "size": size,
            }
        )
    names = {item["name"] for item in artifacts}
    missing = sorted(REQUIRED_FILES - names)
    if missing:
        raise ValueError("missing release-candidate artifacts: " + ", ".join(missing))
    dmgs = [name for name in names if name.startswith("Slipstream_") and name.endswith(".dmg")]
    if len(dmgs) != 1:
        raise ValueError("release candidate must contain exactly one Slipstream DMG")
    return artifacts


def _validate_candidate_metadata(
    *,
    candidate_dir: Path,
    repository: str,
    version: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
) -> dict:
    tag = _candidate_tag(source_commit)
    sbom = _read_object(candidate_dir / SBOM_NAME, "candidate SBOM")
    sbom_summary = make_release_sbom.validate_spdx_document(
        sbom,
        version=version,
        tag=tag,
        repository=repository,
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    audit_summary = dependency_audit.validate_audit_report_file(
        report_path=candidate_dir / AUDIT_NAME,
        policy_path=dependency_audit.DEFAULT_POLICY,
        sbom_path=candidate_dir / SBOM_NAME,
        source_commit=source_commit,
        target=target,
    )
    return {
        "sbom_packages": sbom_summary["package_count"],
        "audited_packages": audit_summary["packages_scanned"],
    }


def build_manifest(
    *,
    candidate_dir: Path,
    repository: str,
    version: str,
    source_commit: str,
    source_tree: str,
    source_archive_sha256: str,
    source_date_epoch: int,
    target: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    app_tree: Path,
) -> dict:
    _validate_identity(
        repository=repository,
        version=version,
        source_commit=source_commit,
        source_tree=source_tree,
        source_archive_sha256=source_archive_sha256,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    if workflow_run_id <= 0 or workflow_run_attempt <= 0:
        raise ValueError("workflow run identity must be positive")
    artifacts = collect_candidate_artifacts(candidate_dir)
    metadata = _validate_candidate_metadata(
        candidate_dir=candidate_dir,
        repository=repository,
        version=version,
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": _candidate_tag(source_commit),
        "version": version,
        "target": target,
        "source": {
            "repository": repository,
            "commit": source_commit,
            "tree": source_tree,
            "archive_sha256": source_archive_sha256,
            "source_date_epoch": source_date_epoch,
            "created_at": make_release_sbom.utc_timestamp(source_date_epoch),
        },
        "builder": {
            "workflow": BUILD_WORKFLOW,
            "run_id": workflow_run_id,
            "run_attempt": workflow_run_attempt,
        },
        "metadata": metadata,
        "app_tree_sha256": deterministic_tree_sha256(app_tree),
        "artifacts": artifacts,
    }


def validate_manifest(
    *,
    candidate_dir: Path,
    repository: str,
    version: str,
    source_commit: str,
    source_tree: str,
    source_archive_sha256: str,
    source_date_epoch: int,
    target: str,
    expected_workflow_run_id: int | None = None,
    expected_workflow_run_attempt: int | None = None,
    app_tree: Path | None = None,
) -> dict:
    manifest = _read_object(candidate_dir / MANIFEST_NAME, "candidate manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported release-candidate manifest schema")
    _validate_identity(
        repository=repository,
        version=version,
        source_commit=source_commit,
        source_tree=source_tree,
        source_archive_sha256=source_archive_sha256,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    expected_source = {
        "repository": repository,
        "commit": source_commit,
        "tree": source_tree,
        "archive_sha256": source_archive_sha256,
        "source_date_epoch": source_date_epoch,
        "created_at": make_release_sbom.utc_timestamp(source_date_epoch),
    }
    if manifest.get("candidate_id") != _candidate_tag(source_commit):
        raise ValueError("candidate ID does not match source commit")
    if manifest.get("version") != version or manifest.get("target") != target:
        raise ValueError("candidate version or target does not match source")
    if manifest.get("source") != expected_source:
        raise ValueError("candidate source commit, tree, or archive digest does not match")
    builder = manifest.get("builder")
    if not isinstance(builder, dict) or builder.get("workflow") != BUILD_WORKFLOW:
        raise ValueError("candidate builder workflow is invalid")
    if not isinstance(builder.get("run_id"), int) or builder["run_id"] <= 0:
        raise ValueError("candidate builder run ID is invalid")
    if expected_workflow_run_id is not None and builder["run_id"] != expected_workflow_run_id:
        raise ValueError("candidate builder run ID does not match downloaded workflow")
    if not isinstance(builder.get("run_attempt"), int) or builder["run_attempt"] <= 0:
        raise ValueError("candidate builder run attempt is invalid")
    if (
        expected_workflow_run_attempt is not None
        and builder["run_attempt"] != expected_workflow_run_attempt
    ):
        raise ValueError(
            "candidate builder run attempt does not match downloaded workflow"
        )
    artifacts = collect_candidate_artifacts(candidate_dir)
    if manifest.get("artifacts") != artifacts:
        raise ValueError("candidate artifact hashes, sizes, or names do not match")
    metadata = _validate_candidate_metadata(
        candidate_dir=candidate_dir,
        repository=repository,
        version=version,
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    if manifest.get("metadata") != metadata:
        raise ValueError("candidate dependency metadata summary does not match")
    app_tree_sha256 = manifest.get("app_tree_sha256")
    if not isinstance(app_tree_sha256, str) or not HEX_SHA256.fullmatch(app_tree_sha256):
        raise ValueError("candidate app tree digest is invalid")
    if app_tree is not None and app_tree_sha256 != deterministic_tree_sha256(app_tree):
        raise ValueError("candidate app tree digest does not match unpacked application")
    manifest_sha256, manifest_size = make_release_manifest.hash_regular_file(
        candidate_dir / MANIFEST_NAME
    )
    return {
        "candidate_id": manifest["candidate_id"],
        "manifest_sha256": manifest_sha256,
        "manifest_size": manifest_size,
        "builder_run_id": builder["run_id"],
        "builder_run_attempt": builder["run_attempt"],
        "artifact_count": len(artifacts),
    }


def build_qualification_proof(
    *,
    candidate_dir: Path,
    qualification_run_id: int,
    qualification_run_attempt: int,
    qualification_workflow: str = QUALIFICATION_WORKFLOW,
    expected_candidate_run_attempt: int | None = None,
    app_tree: Path | None = None,
) -> dict:
    if qualification_run_id <= 0 or qualification_run_attempt <= 0:
        raise ValueError("qualification run identity must be positive")
    if (
        not isinstance(qualification_workflow, str)
        or qualification_workflow not in QUALIFICATION_WORKFLOWS
    ):
        raise ValueError("qualification workflow is not an approved protected gate")
    manifest = _read_object(candidate_dir / MANIFEST_NAME, "candidate manifest")
    source = manifest.get("source")
    builder = manifest.get("builder")
    if not isinstance(source, dict) or not isinstance(builder, dict):
        raise ValueError("candidate manifest identity is incomplete")
    validate_manifest(
        candidate_dir=candidate_dir,
        repository=source.get("repository", ""),
        version=manifest.get("version", ""),
        source_commit=source.get("commit", ""),
        source_tree=source.get("tree", ""),
        source_archive_sha256=source.get("archive_sha256", ""),
        source_date_epoch=source.get("source_date_epoch", -1),
        target=manifest.get("target", ""),
        expected_workflow_run_id=builder.get("run_id"),
        expected_workflow_run_attempt=expected_candidate_run_attempt,
        app_tree=app_tree,
    )
    manifest_sha256, _ = make_release_manifest.hash_regular_file(
        candidate_dir / MANIFEST_NAME
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": manifest.get("candidate_id"),
        "candidate_manifest_sha256": manifest_sha256,
        "source_commit": source.get("commit"),
        "source_tree": source.get("tree"),
        "candidate_build_run_id": builder.get("run_id"),
        "candidate_build_run_attempt": builder.get("run_attempt"),
        "qualification": {
            "workflow": qualification_workflow,
            "run_id": qualification_run_id,
            "run_attempt": qualification_run_attempt,
            "result": "passed",
        },
    }


def validate_qualification_proof(
    *,
    candidate_dir: Path,
    proof_path: Path,
    expected_qualification_run_id: int | None = None,
    expected_qualification_run_attempt: int | None = None,
    expected_qualification_workflow: str | None = None,
    expected_candidate_run_attempt: int | None = None,
) -> dict:
    proof = _read_object(proof_path, "release qualification proof")
    qualification = proof.get("qualification")
    if not isinstance(qualification, dict):
        raise ValueError("qualification proof identity is invalid")
    run_id = qualification.get("run_id")
    run_attempt = qualification.get("run_attempt")
    workflow = qualification.get("workflow")
    if not isinstance(run_id, int) or isinstance(run_id, bool):
        raise ValueError("qualification proof run ID is invalid")
    if not isinstance(run_attempt, int) or isinstance(run_attempt, bool):
        raise ValueError("qualification proof run attempt is invalid")
    if not isinstance(workflow, str) or workflow not in QUALIFICATION_WORKFLOWS:
        raise ValueError("qualification proof workflow is invalid")
    if (
        expected_qualification_workflow is not None
        and workflow != expected_qualification_workflow
    ):
        raise ValueError(
            "qualification proof workflow does not match downloaded workflow"
        )
    expected = build_qualification_proof(
        candidate_dir=candidate_dir,
        qualification_run_id=(
            expected_qualification_run_id
            if expected_qualification_run_id is not None
            else run_id
        ),
        qualification_run_attempt=run_attempt,
        qualification_workflow=workflow,
        expected_candidate_run_attempt=expected_candidate_run_attempt,
        app_tree=None,
    )
    if proof != expected:
        raise ValueError("qualification proof does not match the exact candidate")
    if run_id <= 0 or run_attempt <= 0:
        raise ValueError("qualification proof run identity is invalid")
    if (
        expected_qualification_run_attempt is not None
        and run_attempt != expected_qualification_run_attempt
    ):
        raise ValueError(
            "qualification proof run attempt does not match downloaded workflow"
        )
    return {
        "candidate_id": proof["candidate_id"],
        "candidate_build_run_id": proof["candidate_build_run_id"],
        "candidate_build_run_attempt": proof["candidate_build_run_attempt"],
        "qualification_run_id": proof["qualification"]["run_id"],
        "qualification_run_attempt": proof["qualification"]["run_attempt"],
    }


def _identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-archive-sha256", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument(
        "--target", choices=tuple(make_release_manifest.TARGETS), required=True
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    _identity_arguments(create)
    create.add_argument("--workflow-run-id", required=True, type=int)
    create.add_argument("--workflow-run-attempt", required=True, type=int)
    create.add_argument("--app-tree", required=True, type=Path)
    verify = subparsers.add_parser("verify")
    _identity_arguments(verify)
    verify.add_argument("--expected-workflow-run-id", type=int)
    verify.add_argument("--expected-workflow-run-attempt", type=int)
    verify.add_argument("--app-tree", type=Path)
    proof = subparsers.add_parser("create-proof")
    proof.add_argument("--candidate-dir", required=True, type=Path)
    proof.add_argument("--output", required=True, type=Path)
    proof.add_argument("--qualification-run-id", required=True, type=int)
    proof.add_argument("--qualification-run-attempt", required=True, type=int)
    proof.add_argument(
        "--qualification-workflow",
        choices=tuple(sorted(QUALIFICATION_WORKFLOWS)),
        default=QUALIFICATION_WORKFLOW,
    )
    proof.add_argument("--expected-candidate-run-attempt", required=True, type=int)
    proof.add_argument("--app-tree", required=True, type=Path)
    verify_proof = subparsers.add_parser("verify-proof")
    verify_proof.add_argument("--candidate-dir", required=True, type=Path)
    verify_proof.add_argument("--proof", required=True, type=Path)
    verify_proof.add_argument("--expected-qualification-run-id", type=int)
    verify_proof.add_argument("--expected-qualification-run-attempt", type=int)
    verify_proof.add_argument(
        "--expected-qualification-workflow",
        choices=tuple(sorted(QUALIFICATION_WORKFLOWS)),
    )
    verify_proof.add_argument("--expected-candidate-run-attempt", type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "create":
        manifest = build_manifest(
            candidate_dir=args.candidate_dir,
            repository=args.repository,
            version=args.version,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            source_archive_sha256=args.source_archive_sha256,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            app_tree=args.app_tree,
        )
        _write_json(args.candidate_dir / MANIFEST_NAME, manifest)
        result = validate_manifest(
            candidate_dir=args.candidate_dir,
            repository=args.repository,
            version=args.version,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            source_archive_sha256=args.source_archive_sha256,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            expected_workflow_run_id=args.workflow_run_id,
            app_tree=args.app_tree,
        )
    elif args.command == "verify":
        result = validate_manifest(
            candidate_dir=args.candidate_dir,
            repository=args.repository,
            version=args.version,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            source_archive_sha256=args.source_archive_sha256,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            expected_workflow_run_id=args.expected_workflow_run_id,
            expected_workflow_run_attempt=args.expected_workflow_run_attempt,
            app_tree=args.app_tree,
        )
    elif args.command == "create-proof":
        proof = build_qualification_proof(
            candidate_dir=args.candidate_dir,
            qualification_run_id=args.qualification_run_id,
            qualification_run_attempt=args.qualification_run_attempt,
            qualification_workflow=args.qualification_workflow,
            expected_candidate_run_attempt=args.expected_candidate_run_attempt,
            app_tree=args.app_tree,
        )
        _write_json(args.output, proof)
        result = proof
    else:
        result = validate_qualification_proof(
            candidate_dir=args.candidate_dir,
            proof_path=args.proof,
            expected_qualification_run_id=args.expected_qualification_run_id,
            expected_qualification_run_attempt=(
                args.expected_qualification_run_attempt
            ),
            expected_qualification_workflow=(
                args.expected_qualification_workflow
            ),
            expected_candidate_run_attempt=args.expected_candidate_run_attempt,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

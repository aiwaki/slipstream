"""Bounded immutable transport for policy-pinned source-owned review evidence.

This verifies the exact evidence catalog and snapshots, not the source/SPDX
semantics or the truth of a review conclusion. dependency_audit owns those gates.
Only canonical, uncompressed regular USTAR members are accepted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tarfile
import tempfile

import geph_native_sqlite_bundle as transport
import geph_source_owned_advisories as review

BUNDLE_NAME = "geph5-client-source-review-evidence.tar"
MANIFEST = "__slipstream_source_review_bundle__.json"
SCOPE = "source-owned-review-evidence-bundle"
MAX_MEMBERS = review.MAX_EVIDENCE_FILES + 2
MAX_MANIFEST_BYTES = 64 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = (review.MAX_EVIDENCE_TOTAL + review.MAX_REVIEW_BYTES
                    + MAX_MANIFEST_BYTES + MAX_MEMBERS * 1024 + 1024)
ZERO_BLOCK = b"\0" * 512


def _header(name: str, size: int) -> bytes:
    transport._name(name)
    limit = (MAX_MANIFEST_BYTES if name == MANIFEST else
             review.MAX_REVIEW_BYTES if name == "review.json" else review.MAX_EVIDENCE_BYTES)
    if type(size) is not int or not 0 < size <= limit:
        raise ValueError("source review bundle member exceeds size bound")
    return transport._header(name, size)


def _encode(files: dict[str, bytes]) -> bytes:
    if not 1 <= len(files) <= MAX_MEMBERS:
        raise ValueError("source review bundle member count exceeds bound")
    parts, total = [], 1024
    for name, payload in sorted(files.items()):
        header = _header(name, len(payload))
        padding = b"\0" * (-len(payload) % 512)
        total += 512 + len(payload) + len(padding)
        if total > MAX_BUNDLE_BYTES:
            raise ValueError("source review bundle exceeds total size bound")
        parts.extend((header, payload, padding))
    return b"".join([*parts, ZERO_BLOCK, ZERO_BLOCK])


def _decode(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_BUNDLE_BYTES or len(payload) % 512:
        raise ValueError("invalid source review bundle size/alignment")
    files, offset, previous = {}, 0, ""
    while offset + 512 <= len(payload):
        header = payload[offset:offset + 512]
        if header == ZERO_BLOCK:
            if not files or payload[offset:] != ZERO_BLOCK * 2:
                raise ValueError("source review bundle requires exactly two terminator blocks")
            return files
        try:
            item = tarfile.TarInfo.frombuf(header, "ascii", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
            raise ValueError("invalid source review bundle header") from exc
        name = transport._name(item.name)
        # Header equality rejects links, directories, sparse/PAX/GNU records,
        # base-256 fields and noncanonical metadata without tar extraction.
        if item.type != tarfile.REGTYPE or header != _header(name, item.size):
            raise ValueError("source review bundle requires canonical regular USTAR files")
        if name <= previous or name in files or len(files) >= MAX_MEMBERS:
            raise ValueError("source review bundle has duplicate/unordered or excess members")
        end = offset + 512 + item.size
        padded_end = end + (-item.size % 512)
        if padded_end > len(payload) or any(payload[end:padded_end]):
            raise ValueError("source review bundle is truncated or has nonzero padding")
        files[name] = payload[offset + 512:end]
        previous, offset = name, padded_end
    raise ValueError("source review bundle terminator is missing")


def _snapshot(policy_entry: dict, root: Path) -> dict[str, bytes]:
    """Use the review helper's catalog and verified bytes as the sole closure."""
    fd = review.physical._open_physical(root, directory=True)
    try:
        identity = os.fstat(fd)
        document, records, payloads = review._bundle(policy_entry, root, None)
        if not isinstance(document["binding"], dict) or document["binding"].get("source_sha256") != policy_entry["source_sha256"]:
            raise ValueError("source review bundle SOURCE binding differs from policy")
        files = {"review.json": payloads["review.json"],
                 **{entry["path"]: payloads[key] for key, entry in records.items()}}
        if MANIFEST in files:
            raise ValueError("reserved source review bundle manifest path")
        for name in files:
            transport._name(name)
        # First reject extras without recursively enumerating unknown trees.
        review._snapshot_inventory(fd, {name: {"path": name} for name in files})
        transport._assert_tree(root, files, identity)
        return files
    finally:
        os.close(fd)


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _manifest(files: dict[str, bytes], policy_entry: dict) -> bytes:
    payload = _json({"schema_version": 1, "scope": SCOPE,
                     "source_sha256": policy_entry["source_sha256"],
                     "review_sha256": policy_entry["review_sha256"],
                     "files": {name: {"size": len(data), "sha256": review._sha(data)}
                               for name, data in sorted(files.items())}})
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ValueError("source review bundle manifest exceeds bound")
    return payload


def _verify_staged(files: dict[str, bytes], policy_entry: dict) -> dict[str, bytes]:
    """Validate untrusted archive bytes before copying into the caller's root."""
    with tempfile.TemporaryDirectory(prefix="source-review-bundle-check-") as temporary:
        root = Path(temporary).resolve() / "evidence"
        identity = transport._mkdir_and_write(root, files)
        verified = _snapshot(policy_entry, root)
        if verified != files:
            raise ValueError("source review bundle differs from the exact evidence catalog")
        transport._assert_tree(root, verified, identity)
        return verified


def _report(root: Path, payload: bytes, files: dict, policy_entry: dict) -> dict:
    return {"root": str(root), "review_sha256": policy_entry["review_sha256"],
            "source_sha256": policy_entry["source_sha256"],
            "bundle_sha256": review._sha(payload), "size": len(payload), "file_count": len(files)}


def pack_bundle(evidence_root: Path, output_path: Path, policy_entry: dict) -> dict:
    """Snapshot exactly the trusted catalog and create a new immutable asset."""
    root = Path(evidence_root).absolute()
    files = _snapshot(policy_entry, root)
    files = _verify_staged(files, policy_entry)
    payload = _encode(files | {MANIFEST: _manifest(files, policy_entry)})
    output = Path(output_path).absolute()
    parent = review.physical._open_physical(output.parent, directory=True)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
    finally:
        os.close(parent)
    if review.read_snapshot(output, MAX_BUNDLE_BYTES) != payload:
        raise ValueError("source review bundle changed during publication")
    return _report(root, payload, files, policy_entry)


def unpack_bundle(bundle_path: Path, output_root: Path, policy_entry: dict) -> dict:
    """Verify a bounded plain archive, then copy snapshots into a fresh tree.

    Partial destination trees are retained on failure, never removed by path;
    a retry requires a fresh output root.
    """
    review._policy(policy_entry, None)
    payload = review.read_snapshot(Path(bundle_path), MAX_BUNDLE_BYTES)
    files = _decode(payload)
    manifest = files.pop(MANIFEST, b"")
    if manifest != _manifest(files, policy_entry):
        raise ValueError("source review bundle manifest or policy binding differs")
    files = _verify_staged(files, policy_entry)
    root = Path(output_root).absolute()
    identity = transport._mkdir_and_write(root, files)
    try:
        if _snapshot(policy_entry, root) != files:
            raise ValueError("source review bundle destination changed")
        transport._assert_tree(root, files, identity)
    except BaseException as exc:
        exc.add_note(f"Unverified evidence retained at {root}; use a fresh destination for retry.")
        raise
    return _report(root, payload, files, policy_entry)


def read_policy(path: Path) -> dict:
    """Read the trusted audit policy, never authority supplied by an archive."""
    policy = review._json(review.read_snapshot(Path(path), MAX_POLICY_BYTES))
    entry = policy.get("source_owned_review")
    review._policy(entry, None)
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, input_name in (("pack", "evidence-root"), ("unpack", "bundle")):
        child = commands.add_parser(command)
        for name in ("policy", input_name, "output"):
            child.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        policy = read_policy(args.policy)
        if args.command == "pack":
            result = pack_bundle(args.evidence_root, args.output, policy)
        else:
            result = unpack_bundle(args.bundle, args.output, policy)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"source-owned review evidence {args.command} failed: {exc}\n")
    print(json.dumps({"scope": SCOPE, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

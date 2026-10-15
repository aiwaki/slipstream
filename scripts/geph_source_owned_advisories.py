"""Offline, exact-source review of the three owned Geph packages.

The trusted policy pins review bytes, not a future Git commit or SPDX hash.
Ancestor OSV results remain ancestor identities; they never manufacture registry
coordinates for local derivatives. This verifies review evidence and coverage,
not the truth of a reviewer-authored security conclusion or legal clearance.
"""
from __future__ import annotations

from datetime import date
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

import geph_native_sqlite as physical
from geph_native_sqlite_advisories import read_snapshot, _snapshot_inventory
import geph_vendor_source as vendor
from make_geph_vendor_sbom import ROOT_SPDX_ID, _source_owned_inventory

MAX_REVIEW_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_TOTAL = 128 * 1024 * 1024
MAX_EVIDENCE_FILES = 128
MAX_FINDINGS = 4096
DECISIONS = {"code_fixed", "code_not_present", "rejected", "unknown", "affected"}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _keys(value: object, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"source-owned {label} fields do not match schema")


def _text(value: object, label: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"source-owned {label} is invalid")
    return value


def _digest(value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("source-owned digest is invalid")


def _json(payload: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("source-owned JSON contains duplicate keys")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("source-owned JSON contains a nonfinite number")
    value = json.loads(payload, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("source-owned JSON must be an object")
    return value


def _relative(value: object) -> str:
    path = _text(value, "evidence path")
    if (path.startswith("/") or "\\" in path or str(PurePosixPath(path)) != path
            or any(p in {".", ".."} for p in path.split("/")) or len(path.split("/")) > 12):
        raise ValueError("source-owned evidence path must be canonical and relative")
    return path


def _list(value: object, label: str, limit: int, *, nonempty: bool = False) -> list:
    if not isinstance(value, list) or len(value) > limit or (nonempty and not value):
        raise ValueError(f"source-owned {label} list is invalid")
    return value


def _policy(policy: dict, evaluated_on: date) -> None:
    _keys(policy, {"schema_version", "source_sha256", "review_sha256", "expires"}, "policy")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise ValueError("source-owned policy schema is invalid")
    _digest(policy["source_sha256"])
    _digest(policy["review_sha256"])
    expiry = _text(policy["expires"], "expiry", 10)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
        raise ValueError("source-owned expiry must be an ISO date")
    if type(evaluated_on) is not date or not evaluated_on <= date.today() <= date.fromisoformat(expiry):
        raise ValueError("source-owned review expired or evaluation date is in the future")


def _bundle(policy: dict, evidence_root: Path, evaluated_on: date) -> tuple[dict, dict, dict]:
    _policy(policy, evaluated_on)
    root = Path(evidence_root).absolute()
    fd = physical._open_physical(root, directory=True)
    os.close(fd)
    review_bytes = read_snapshot(root / "review.json", MAX_REVIEW_BYTES)
    if _sha(review_bytes) != policy["review_sha256"]:
        raise ValueError("source-owned review SHA256 differs from policy")
    review = _json(review_bytes)
    _keys(review, {"schema_version", "binding", "evidence", "ancestors", "osv_evidence", "packages"}, "review")
    if type(review["schema_version"]) is not int or review["schema_version"] != 1:
        raise ValueError("source-owned review schema is invalid")
    records, paths, total = {}, {"review.json"}, 0
    for entry in _list(review["evidence"], "evidence", MAX_EVIDENCE_FILES, nonempty=True):
        _keys(entry, {"id", "path", "size", "sha256", "kind"}, "evidence")
        identity = _text(entry["id"], "evidence ID", 160)
        path = _relative(entry["path"])
        if identity == "review.json" or identity in records or path in paths or path.casefold() in {p.casefold() for p in paths}:
            raise ValueError("source-owned evidence identity/path is duplicated")
        if not isinstance(entry["kind"], str) or entry["kind"] not in {"archive", "osv", "review"}:
            raise ValueError("source-owned evidence kind is invalid")
        if type(entry["size"]) is not int or not 0 < entry["size"] <= MAX_EVIDENCE_BYTES:
            raise ValueError("source-owned evidence size is invalid")
        _digest(entry["sha256"])
        records[identity] = entry
        paths.add(path)
        total += entry["size"]
    if total > MAX_EVIDENCE_TOTAL:
        raise ValueError("source-owned evidence exceeds total size bound")
    for path in paths:
        if any(str(parent).casefold() in {p.casefold() for p in paths} for parent in PurePosixPath(path).parents if str(parent) != "."):
            raise ValueError("source-owned evidence paths overlap")
    payloads = {"review.json": review_bytes}
    for identity, entry in records.items():
        payload = read_snapshot(root / entry["path"], min(entry["size"], MAX_EVIDENCE_BYTES))
        if len(payload) != entry["size"] or _sha(payload) != entry["sha256"]:
            raise ValueError("source-owned evidence differs from reviewed bytes")
        payloads[identity] = payload
    return review, records, payloads


def _binding(source: dict, source_hash: str) -> dict:
    return {"source_sha256": source_hash, "lock_sha256": source["lock_sha256"], "packages": [
        {"path": p["path"], "descriptor_sha256": p["sha256"],
         "files": {f["path"]: f["sha256"] for f in sorted(p["files"], key=lambda f: f["path"])}}
        for p in sorted(source["embedded_packages"]["packages"], key=lambda p: p["path"])
    ]}


def _inventory(sbom: dict, source: dict, source_hash: str, source_commit: str) -> list[dict]:
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("source-owned source commit is invalid")
    expected, files, contains = _source_owned_inventory(source, source_commit, source_hash)
    if len(expected) != 3:
        raise ValueError("source-owned review requires exactly three known packages")
    contains += [{"spdxElementId": ROOT_SPDX_ID, "relationshipType": "CONTAINS",
                  "relatedSpdxElement": p["SPDXID"]} for p in expected]
    if not isinstance(sbom, dict):
        raise ValueError("source-owned SPDX must be an object")
    packages = _list(sbom.get("packages"), "SPDX packages", 16384, nonempty=True)
    actual_files = _list(sbom.get("files"), "SPDX files", 16384, nonempty=True)
    relationships = _list(sbom.get("relationships"), "SPDX relationships", 32768, nonempty=True)
    for entries in (packages, actual_files):
        ids = [_text(item.get("SPDXID"), "SPDX ID") if isinstance(item, dict) else None for item in entries]
        if None in ids or len(ids) != len(set(ids)):
            raise ValueError("source-owned SPDX has invalid or duplicate IDs")
    if {p["SPDXID"] for p in packages} & {f["SPDXID"] for f in actual_files}:
        raise ValueError("source-owned SPDX package/file IDs overlap")
    names, owned_ids = {p["name"] for p in expected}, {p["SPDXID"] for p in expected}
    def owned(item):
        info = item.get("sourceInfo", "{}")
        try:
            info = json.loads(info)
        except (TypeError, ValueError):
            info = None
        return (item["SPDXID"].startswith("SPDXRef-Package-source-") or isinstance(item.get("name"), str) and item["name"] in names
                or isinstance(info, dict) and info.get("kind") == "slipstream-source-owned")
    actual_owned = [p for p in packages if owned(p)]
    if sorted(actual_owned, key=lambda p: p["SPDXID"]) != sorted(expected, key=lambda p: p["SPDXID"]):
        raise ValueError("source-owned SPDX package identity/content differs from SOURCE")
    file_ids = {f["SPDXID"] for f in files}
    selected_files = [f for f in actual_files if f["SPDXID"] in file_ids
                      or str(f.get("fileName", "")).removeprefix("./").startswith("slipstream-vendor/")]
    if sorted(selected_files, key=lambda f: f["SPDXID"]) != sorted(files, key=lambda f: f["SPDXID"]):
        raise ValueError("source-owned SPDX source file inventory differs from SOURCE")
    selected_relations = []
    for relation in relationships:
        if not isinstance(relation, dict):
            raise ValueError("source-owned SPDX relationship is invalid")
        left, right = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
        if not isinstance(left, str) or not isinstance(right, str):
            raise ValueError("source-owned SPDX relationship identity is invalid")
        if (left in file_ids or right in file_ids
                or relation.get("relationshipType") == "CONTAINS" and (left in owned_ids or right in owned_ids)):
            selected_relations.append(relation)
    key = lambda r: (r["spdxElementId"], r.get("relationshipType", ""), r["relatedSpdxElement"])
    if sorted(selected_relations, key=key) != sorted(contains, key=key):
        raise ValueError("source-owned SPDX CONTAINS inventory differs from SOURCE")
    return expected


def _ref(identity: object, kind: str, records: dict, used: set) -> str:
    identity = _text(identity, "evidence reference", 160)
    if identity not in records or records[identity]["kind"] != kind:
        raise ValueError("source-owned evidence reference has wrong identity/kind")
    used.add(identity)
    return identity


def _refs(values: object, records: dict, used: set) -> list[str]:
    refs = [_ref(v, "review", records, used) for v in _list(values, "review evidence", MAX_EVIDENCE_FILES, nonempty=True)]
    if len(refs) != len(set(refs)):
        raise ValueError("source-owned review evidence references are duplicated")
    return sorted(refs)


def _ancestor_archive(descriptor: dict, payload: bytes) -> None:
    provenance = descriptor["provenance"]
    if _sha(payload) != provenance["sha256"]:
        raise ValueError("source-owned ancestor archive differs from provenance")
    expected_root = provenance["name"] + "-" + provenance["version"]
    originals = provenance["original_files"]
    found = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in vendor._safe_members(archive, expected_root):
                path = PurePosixPath(member.name)
                if (str(path) != member.name.rstrip("/") or "\\" in member.name
                        or any(part in {".", "..", ""} for part in member.name.rstrip("/").split("/"))):
                    raise ValueError("source-owned ancestor archive has a noncanonical path")
                relative = str(path.relative_to(expected_root))
                if relative not in originals:
                    continue
                if not member.isfile() or not 0 < member.size <= vendor.MAX_EMBEDDED_FILE_BYTES:
                    raise ValueError("source-owned original source is not a bounded regular file")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("source-owned original source is missing")
                with stream:
                    content = stream.read(vendor.MAX_EMBEDDED_FILE_BYTES + 1)
                if len(content) != member.size or _sha(content) != originals[relative]:
                    raise ValueError("source-owned original source hash differs from provenance")
                found[relative] = content
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ValueError("source-owned ancestor archive is invalid") from exc
    if set(found) != set(originals):
        raise ValueError("source-owned ancestor original file inventory is incomplete")
    retained = next(f["content"].encode() for f in descriptor["files"] if f["path"] == "provenance/Cargo.toml")
    if found["Cargo.toml"] != retained:
        raise ValueError("source-owned original manifest differs from retained bytes")


def _osv(payload: bytes, ancestors: set[tuple[str, str]]) -> dict:
    raw = _json(payload)
    if raw.get("error") or raw.get("errors"):
        raise ValueError("source-owned ancestor OSV contains errors")
    results = _list(raw.get("results"), "OSV results", 64, nonempty=True)
    found = {}
    for group in results:
        if not isinstance(group, dict) or group.get("error") or group.get("errors"):
            raise ValueError("source-owned ancestor OSV result is invalid")
        for entry in _list(group.get("packages"), "OSV packages", 2, nonempty=True):
            if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict) or entry.get("error") or entry.get("errors"):
                raise ValueError("source-owned ancestor OSV package is invalid")
            package = entry["package"]
            identity = (_text(package.get("name"), "OSV package name"), _text(package.get("version"), "OSV package version"))
            if package.get("ecosystem") != "crates.io":
                raise ValueError("source-owned ancestor OSV ecosystem must be crates.io")
            if identity not in ancestors or identity in found:
                raise ValueError("source-owned ancestor OSV identities are missing/duplicate/unexpected")
            findings = {}
            for finding in _list(entry.get("vulnerabilities", []), "OSV vulnerabilities", MAX_FINDINGS):
                if not isinstance(finding, dict):
                    raise ValueError("source-owned ancestor OSV finding is invalid")
                identity_id = _text(finding.get("id"), "OSV advisory ID", 160)
                aliases = [_text(v, "OSV alias", 160) for v in _list(finding.get("aliases", []), "OSV aliases", 256)]
                if identity_id in findings or len(aliases) != len(set(aliases)) or identity_id in aliases:
                    raise ValueError("source-owned ancestor OSV findings/aliases are duplicated")
                findings[identity_id] = {"id": identity_id, "aliases": sorted(aliases)}
            found[identity] = findings
    if set(found) != ancestors:
        raise ValueError("source-owned ancestor OSV identities are incomplete")
    return found


def _findings(values: object, expected: dict | None, records: dict, used: set) -> list[dict]:
    found = {}
    for finding in _list(values, "findings", MAX_FINDINGS):
        _keys(finding, {"id", "disposition", "evidence"} | ({"aliases"} if expected is not None else set()), "finding")
        identity = _text(finding["id"], "finding ID", 160)
        if identity in found or not isinstance(finding["disposition"], str) or finding["disposition"] not in DECISIONS:
            raise ValueError("source-owned finding duplicate/disposition is invalid")
        record = {"id": identity, "disposition": finding["disposition"], "evidence": _refs(finding["evidence"], records, used)}
        if expected is not None:
            aliases = [_text(v, "finding alias", 160) for v in _list(finding["aliases"], "finding aliases", 256)]
            if len(aliases) != len(set(aliases)) or expected.get(identity) != {"id": identity, "aliases": sorted(aliases)}:
                raise ValueError("source-owned inherited finding/aliases differ from ancestor OSV")
            record["aliases"] = sorted(aliases)
        found[identity] = record
    if expected is not None and set(found) != set(expected):
        raise ValueError("source-owned inherited finding coverage is incomplete")
    return [found[key] for key in sorted(found)]


def validate_source_owned_review(policy_entry: dict, *, sbom: dict, source_path: Path,
                                evidence_root: Path, evaluated_on: date, source_commit: str) -> dict:
    review, records, payloads = _bundle(policy_entry, evidence_root, evaluated_on)
    source_bytes = read_snapshot(Path(source_path), vendor.MAX_SOURCE_BYTES)
    source = _json(source_bytes)
    vendor._validate_source_contract(source)
    source_hash = _sha(source_bytes)
    if source_hash != policy_entry["source_sha256"]:
        raise ValueError("source-owned SOURCE SHA256 differs from policy")
    expected_owned = _inventory(sbom, source, source_hash, source_commit)
    binding = _binding(source, source_hash)
    if review["binding"] != binding:
        raise ValueError("source-owned review binding differs from SOURCE/lock/descriptors/files")
    descriptors = {p["path"]: p for p in source["embedded_packages"]["packages"]}
    derivatives = {(p["provenance"]["name"], p["provenance"]["version"]): p for p in descriptors.values() if p["provenance"]["kind"] == "derivative"}
    used, ancestors = set(), set()
    for ancestor in _list(review["ancestors"], "ancestors", 2, nonempty=True):
        _keys(ancestor, {"name", "version", "archive_evidence"}, "ancestor")
        identity = (_text(ancestor["name"], "ancestor name"), _text(ancestor["version"], "ancestor version"))
        if identity not in derivatives or identity in ancestors:
            raise ValueError("source-owned ancestor identities are duplicate/unexpected")
        ancestors.add(identity)
        _ancestor_archive(derivatives[identity], payloads[_ref(ancestor["archive_evidence"], "archive", records, used)])
    if ancestors != set(derivatives) or len(ancestors) != 2:
        raise ValueError("source-owned ancestor coverage is incomplete")
    inherited = _osv(payloads[_ref(review["osv_evidence"], "osv", records, used)], ancestors)
    packages = {}
    unresolved = affected = 0
    for package in _list(review["packages"], "packages", 3, nonempty=True):
        _keys(package, {"path", "source_review", "inherited_findings", "manual_findings"}, "package review")
        path = _text(package["path"], "package path")
        if path not in descriptors or path in packages:
            raise ValueError("source-owned package review identity is duplicate/unexpected")
        descriptor = descriptors[path]
        source_review = package["source_review"]
        _keys(source_review, {"disposition", "files", "evidence"}, "source review")
        if source_review["disposition"] not in ("reviewed", "unresolved"):
            raise ValueError("source-owned source review disposition is invalid")
        paths = [_text(v, "reviewed source file") for v in _list(source_review["files"], "reviewed files", 64, nonempty=True)]
        if len(paths) != len(set(paths)) or set(paths) != {f["path"] for f in descriptor["files"]}:
            raise ValueError("source-owned source review file coverage is incomplete")
        source_review = {"disposition": source_review["disposition"], "files": sorted(paths), "evidence": _refs(source_review["evidence"], records, used)}
        provenance = descriptor["provenance"]
        ancestor = {"ecosystem": "crates.io", "name": provenance["name"], "version": provenance["version"]} if provenance["kind"] == "derivative" else None
        expected = inherited[(ancestor["name"], ancestor["version"])] if ancestor else {}
        findings = _findings(package["inherited_findings"], expected, records, used)
        manual = _findings(package["manual_findings"], None, records, used)
        unresolved += int(source_review["disposition"] == "unresolved")
        unresolved += sum(f["disposition"] == "unknown" for f in findings + manual)
        affected += sum(f["disposition"] == "affected" for f in findings + manual)
        packages[path] = {"path": path, "package_id": "SPDXRef-Package-source-" + descriptor["sha256"],
                          "name": descriptor["name"], "version": descriptor["version"], "ancestor": ancestor,
                          "source_review": source_review, "inherited_findings": findings, "manual_findings": manual}
    if set(packages) != set(descriptors):
        raise ValueError("source-owned package review coverage is incomplete")
    if used != set(records):
        raise ValueError("source-owned evidence catalog contains unreferenced files")
    return {"schema_version": 1, "package_ids": sorted(p["SPDXID"] for p in expected_owned),
            "review_sha256": policy_entry["review_sha256"], "binding": binding,
            "packages": [packages[path] for path in sorted(packages)],
            "summary": {"packages": 3, "unresolved": unresolved, "affected": affected},
            "status": "fail" if unresolved or affected else "pass"}


def retain_source_owned_review_evidence(policy_entry: dict, evidence_root: Path, destination: Path) -> dict:
    """Snapshot policy-bound regular bytes into a fresh root; never overwrite."""
    _, records, payloads = _bundle(policy_entry, evidence_root, date.today())
    destination = Path(destination).absolute()
    parent_fd = physical._open_physical(destination.parent, directory=True)
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
        root_fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    files = {"review.json": payloads["review.json"], **{entry["path"]: payloads[identity] for identity, entry in records.items()}}
    try:
        for path, payload in sorted(files.items()):
            fd = os.dup(root_fd)
            try:
                parts = path.split("/")
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                output_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(output_fd, "wb") as stream:
                    stream.write(payload)
            finally:
                os.close(fd)
        before, after = os.fstat(root_fd), destination.lstat()
        if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("source-owned retained root changed during copy")
        _snapshot_inventory(root_fd, {path: {"path": path} for path in files})
        for path, payload in files.items():
            if read_snapshot(destination / path, len(payload)) != payload:
                raise ValueError("source-owned retained bytes differ after copy")
    finally:
        os.close(root_fd)
    return {"root": str(destination), "review_sha256": policy_entry["review_sha256"]}

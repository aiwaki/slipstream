"""Offline enforcement of an explicitly reviewed native SQLite advisory census.

Policy is the review authority. Evidence roles do not infer fix semantics. A
consumer reconstructs this result from policy and independently verified native
proof; a producer additionally snapshots the named advisory evidence.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

import geph_native_sqlite as native
import geph_native_sqlite_build as build
import geph_vendor_source as vendor
from make_release_sbom import _cargo_registry_component

MAX_REVIEW_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_TOTAL = 256 * 1024 * 1024
MAX_EVIDENCE_FILES = 2048
MAX_GROUPS = 4096
ROLES = {"census", "aliases", "receipt", "primary", "exact_source",
         "positive_control", "target_exclusion", "review"}
DECISIONS = {"unknown", "affected", "code_fixed", "code_not_present", "rejected", "excluded"}
IDENTITY_FIELDS = ("id", "aliases", "identity", "census_verdict", "conflicts")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _keys(value: object, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"native advisory {label} fields do not match schema")


def _text(value: object, label: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"native advisory {label} is invalid")
    return value


def _digest(value: object) -> None:
    native._digest(value, "advisory")


def _json(payload: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("native advisory JSON has duplicate keys")
            value[key] = item
        return value
    def invalid(value):
        raise ValueError("native advisory JSON has a nonfinite number")
    value = json.loads(payload, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("native advisory JSON must be an object")
    return value


def read_snapshot(path: Path, limit: int) -> bytes:
    """One pinned regular inode, with size and change checks before accepting bytes."""
    fd = native._open_physical(Path(path))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError("native advisory input is not a bounded regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            payload = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(payload) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise ValueError("native advisory input changed during snapshot")
        return payload
    finally:
        os.close(fd)


def _relative(value: object) -> str:
    path = _text(value, "evidence path", 512)
    parts = PurePosixPath(path).parts
    if (not parts or path.startswith("/") or "\\" in path
            or any(p in {".", ".."} for p in path.split("/"))
            or str(PurePosixPath(path)) != path or len(parts) > 12):
        raise ValueError("native advisory evidence path is not a canonical relative path")
    return path


def _catalog(review: dict) -> dict[str, dict]:
    entries = review.get("evidence")
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_EVIDENCE_FILES:
        raise ValueError("native advisory evidence inventory is invalid")
    records, paths, total = {}, set(), 0
    for item in entries:
        _keys(item, {"id", "path", "size", "sha256", "role", "target"}, "evidence")
        identity = _text(item["id"], "evidence ID", 160)
        path = _relative(item["path"])
        if identity in records or path in paths:
            raise ValueError("native advisory evidence identity/path is duplicated")
        if type(item["size"]) is not int or not 0 < item["size"] <= MAX_EVIDENCE_BYTES:
            raise ValueError("native advisory evidence size is invalid")
        _digest(item["sha256"])
        if item["role"] not in ROLES or item["target"] not in (None, *native.TARGETS):
            raise ValueError("native advisory evidence role/target is invalid")
        if item["role"] == "target_exclusion" and item["target"] is None:
            raise ValueError("native advisory target exclusion requires a target")
        records[identity] = item
        paths.add(path)
        total += item["size"]
    if total > MAX_EVIDENCE_TOTAL:
        raise ValueError("native advisory evidence exceeds total size bound")
    for path in paths:
        if any(str(p) in paths for p in PurePosixPath(path).parents if str(p) != "."):
            raise ValueError("native advisory evidence paths overlap")
    return records


def _evidence_bytes(root: Path, item: dict) -> bytes:
    payload = read_snapshot(root / item["path"], MAX_EVIDENCE_BYTES)
    if len(payload) != item["size"] or build.sha(payload) != item["sha256"]:
        raise ValueError("native advisory evidence differs from reviewed bytes")
    return payload


def _snapshot_inventory(root_fd: int, records: dict[str, dict]) -> None:
    expected = {}
    for item in records.values():
        tree = expected
        parts = item["path"].split("/")
        for part in parts[:-1]:
            tree = tree.setdefault(part, {})
        tree[parts[-1]] = None
    def visit(fd, tree):
        seen = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                # Expected children + one entries maximum; never recurse extras.
                if entry.name not in tree or entry.name in seen:
                    raise ValueError("native advisory snapshot has unexpected entries")
                seen.add(entry.name)
                child_tree = tree[entry.name]
                child = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                | (os.O_DIRECTORY if child_tree is not None else 0), dir_fd=fd)
                try:
                    if child_tree is None:
                        if not stat.S_ISREG(os.fstat(child).st_mode):
                            raise ValueError("native advisory snapshot file is not regular")
                    else:
                        visit(child, child_tree)
                finally:
                    os.close(child)
        if seen != set(tree):
            raise ValueError("native advisory snapshot has missing entries")
    visit(root_fd, expected)


def retain_native_review_evidence(review: dict, evidence_root: Path, output_root: Path) -> dict:
    """Copy only reviewed files to a fresh owned root; retain partial output on failure."""
    records = _catalog(review)
    root = build._root(Path(evidence_root))
    destination = Path(output_root).absolute()
    build._root(destination.parent)
    destination.mkdir(mode=0o700)
    root_fd = native._open_physical(destination, directory=True)
    try:
        for item in records.values():
            payload = _evidence_bytes(root, item)
            fd = os.dup(root_fd)
            try:
                parts = item["path"].split("/")
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                output_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=fd)
                with os.fdopen(output_fd, "wb") as stream:
                    stream.write(payload)
            finally:
                os.close(fd)
        # Reading through the caller path detects replacement of the owned root
        # and binds exactly the bytes the next validator will consume.
        info, current = os.fstat(root_fd), destination.lstat()
        if not stat.S_ISDIR(current.st_mode) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("native advisory snapshot root changed")
        _snapshot_inventory(root_fd, records)
        for item in records.values():
            _evidence_bytes(destination, item)
    finally:
        os.close(root_fd)
    return {"root": str(destination), "files": [dict(item) for item in records.values()],
            "bytes": sum(item["size"] for item in records.values())}


def group_identity_sha256(groups: list[dict]) -> str:
    return build.sha(canonical([{k: group[k] for k in IDENTITY_FIELDS}
                               for group in sorted(groups, key=lambda g: g["id"])]))


def _review_schema(review: dict, evaluated_on: date, verification_on: date) -> tuple[dict, list[dict]]:
    _keys(review, {"schema_version", "expires", "binding", "census", "evidence", "groups"}, "review")
    if len(canonical(review)) > MAX_REVIEW_BYTES or type(review["schema_version"]) is not int or review["schema_version"] != 1:
        raise ValueError("native advisory review schema/size is invalid")
    if type(evaluated_on) is not date or type(verification_on) is not date:
        raise ValueError("native advisory evaluation dates are invalid")
    census = review["census"]
    _keys(census, {"publication_cutoff", "census_ref", "aliases_ref", "receipt_ref",
                   "groups_sha256", "groups_total", "native_groups"}, "census")
    cutoff = _text(census["publication_cutoff"], "cutoff", 40)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", cutoff):
        raise ValueError("native advisory census cutoff must be UTC")
    cutoff_date = datetime.fromisoformat(cutoff.replace("Z", "+00:00")).date()
    expires = date.fromisoformat(review["expires"])
    if not cutoff_date <= evaluated_on <= verification_on <= expires:
        raise ValueError("native advisory review is expired or dates do not match cutoff")
    records = _catalog(review)
    for name, role in (("census_ref", "census"), ("aliases_ref", "aliases"), ("receipt_ref", "receipt")):
        if census[name] not in records or records[census[name]]["role"] != role:
            raise ValueError("native advisory census evidence reference is invalid")
    groups = review["groups"]
    if not isinstance(groups, list) or not 0 < len(groups) <= MAX_GROUPS:
        raise ValueError("native advisory groups are invalid")
    ids, aliases, used = set(), set(), {census[k] for k in ("census_ref", "aliases_ref", "receipt_ref")}
    for group in groups:
        _keys(group, {"id", "aliases", "identity", "census_verdict", "decision", "review_status",
                      "source_verdict", "rationale", "evidence", "conflicts", "conflicts_resolved"}, "group")
        identity = _text(group["id"], "group ID", 160)
        if identity in ids:
            raise ValueError("native advisory group is duplicated")
        ids.add(identity)
        members = group["aliases"]
        if (not isinstance(members, list) or not 0 < len(members) <= 128
                or any(not isinstance(x, str) for x in members)
                or members != sorted(set(members)) or identity not in members):
            raise ValueError("native advisory aliases must be exact sorted unique identities")
        for member in members:
            _text(member, "alias", 160)
        if aliases.intersection(members):
            raise ValueError("native advisory alias belongs to multiple groups")
        aliases.update(members)
        if group["identity"] not in {"native", "excluded"} or group["decision"] not in DECISIONS:
            raise ValueError("native advisory identity/decision is invalid")
        if group["review_status"] not in {"adjudicated", "census_only"} or type(group["conflicts_resolved"]) is not bool:
            raise ValueError("native advisory review status is invalid")
        for key in ("census_verdict", "source_verdict", "rationale"):
            _text(group[key], key)
        conflicts = group["conflicts"]
        if not isinstance(conflicts, list) or len(conflicts) > 64 or len(set(conflicts)) != len(conflicts):
            raise ValueError("native advisory conflicts are invalid")
        for conflict in conflicts:
            _text(conflict, "conflict")
        references = group["evidence"]
        if (not isinstance(references, list) or not references or any(not isinstance(x, str) for x in references)
                or len(set(references)) != len(references) or any(x not in records for x in references)):
            raise ValueError("native advisory decision evidence is missing/duplicated/unknown")
        used.update(references)
        if group["identity"] == "excluded":
            if (group["decision"] != "excluded" or group["review_status"] != "adjudicated"
                    or group["census_verdict"] != "outside_native_component_scope"):
                raise ValueError("native advisory exclusion is not explicitly reviewed")
        elif group["decision"] == "excluded" or group["census_verdict"] == "outside_native_component_scope":
            raise ValueError("native advisory native group cannot be excluded")
        if group["review_status"] == "adjudicated" and group["decision"] in {"code_fixed", "code_not_present", "rejected"}:
            roles = {records[x]["role"] for x in references}
            required = {"primary", "exact_source"} if group["decision"] == "code_fixed" else {"primary"}
            if group["decision"] == "code_not_present":
                required = {"positive_control", "target_exclusion"}
                targets = {records[x]["target"] for x in references if records[x]["role"] == "target_exclusion"}
                if targets != set(native.TARGETS):
                    raise ValueError("native advisory code absence lacks both target proofs")
            if not required <= roles or (conflicts and not group["conflicts_resolved"]):
                raise ValueError("native advisory decision lacks required evidence/conflict resolution")
    if used != set(records):
        raise ValueError("native advisory evidence inventory has unreferenced entries")
    if (type(census["groups_total"]) is not int or census["groups_total"] != len(groups)
            or type(census["native_groups"]) is not int
            or census["native_groups"] != sum(g["identity"] == "native" for g in groups)
            or not 0 < census["native_groups"] <= census["groups_total"]):
        raise ValueError("native advisory census group counts differ")
    _digest(census["groups_sha256"])
    if census["groups_sha256"] != group_identity_sha256(groups):
        raise ValueError("native advisory census identity projection differs")
    return records, sorted(groups, key=lambda g: g["id"])


def _verify_census(review: dict, payloads: dict[str, bytes]) -> None:
    """Replay identity membership, without running the research analyzer."""
    scope = review["census"]
    census, aliases, receipt = (_json(payloads[scope[k]]) for k in ("census_ref", "aliases_ref", "receipt_ref"))
    if census.get("scope", {}).get("publication_cutoff") != scope["publication_cutoff"]:
        raise ValueError("native advisory retained census cutoff differs")
    if not isinstance(receipt.get("bindings"), list) or not receipt["bindings"]:
        raise ValueError("native advisory retained census receipt has no bindings")
    for key in ("census_ref", "aliases_ref"):
        payload = payloads[scope[key]]
        if not any(isinstance(item, dict) and item.get("sha256") == build.sha(payload)
                   and item.get("bytes") == len(payload) for item in receipt["bindings"]):
            raise ValueError("native advisory retained census receipt does not bind census/aliases")
    rows = census.get("records")
    alias_groups = aliases.get("groups")
    if not isinstance(rows, list) or not isinstance(alias_groups, list) or len(rows) != scope["groups_total"] or len(alias_groups) != len(rows):
        raise ValueError("native advisory retained census inventory differs")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in by_id:
            raise ValueError("native advisory retained census duplicate/missing record")
        by_id[row["id"]] = row
    projection, keys, row_ids = [], set(), set()
    for group in alias_groups:
        identity = group["key"]
        census_ids = group.get("census_cve_ids")
        if (identity in keys or not isinstance(census_ids, list) or len(census_ids) != 1
                or census_ids[0] not in by_id or census_ids[0] in row_ids
                or census_ids[0] not in group["ids"]):
            raise ValueError("native advisory retained alias group differs")
        keys.add(identity)
        row_id = census_ids[0]
        row_ids.add(row_id)
        row = by_id[row_id]
        identity_class = row["identity_class"]
        if identity_class not in {"other_product", "upstream_sqlite_candidate", "upstream_auxiliary_tool_or_extension", "embedded_upstream_or_fork_unknown"}:
            raise ValueError("native advisory retained identity class is unsupported")
        is_native = identity_class != "other_product"
        if row["alias_group"] != identity or group.get("native_or_ambiguous_ids") != ([row_id] if is_native else []):
            raise ValueError("native advisory retained alias membership differs")
        projection.append({"id": identity, "aliases": group["ids"], "identity": "native" if is_native else "excluded",
                           "census_verdict": row["exact_3_53_2_source_verdict"], "conflicts": row["observations"]})
    if group_identity_sha256(projection) != scope["groups_sha256"]:
        raise ValueError("native advisory retained census does not match reviewed groups")


def _native_sbom(sbom: dict, descriptor: dict, source_hash: str, proof: dict, root: Path) -> str:
    descriptor_hash = native.descriptor_sha256(descriptor)
    package_id = "SPDXRef-Package-native-sqlite-" + descriptor_hash
    packages, files, relationships = (sbom.get(k) for k in ("packages", "files", "relationships"))
    if not all(isinstance(x, list) for x in (packages, files, relationships)):
        raise ValueError("native advisory SBOM inventories are required")
    for entries in (packages, files):
        ids = [entry.get("SPDXID") for entry in entries if isinstance(entry, dict)]
        if len(ids) != len(entries) or any(not isinstance(x, str) or not x for x in ids) or len(set(ids)) != len(ids):
            raise ValueError("native advisory SBOM inventory identities are invalid/duplicated")
    selected = [p for p in packages if p["SPDXID"] == package_id]
    if len(selected) != 1:
        raise ValueError("native advisory SBOM lacks the exact native package")
    package = selected[0]
    source_info = {"kind": "slipstream-native-sqlite", "source_sha256": source_hash,
                   "descriptor_sha256": descriptor_hash, "sqlite_source_id": descriptor["source_id"],
                   "native_receipt_sha256": proof["receipt_sha256"], "final_binary_sha256": proof["final_binary_sha256"],
                   "targets": proof["targets"]}
    if _json(_text(package.get("sourceInfo"), "SBOM sourceInfo").encode()) != source_info:
        raise ValueError("native advisory SBOM sourceInfo differs from verified proof")
    expected = {"name": "sqlite", "versionInfo": descriptor["version"],
                "downloadLocation": descriptor["archive"]["url"], "filesAnalyzed": True,
                "checksums": [{"algorithm": "SHA256", "checksumValue": descriptor["archive"]["sha256"]}]}
    if any(package.get(k) != v for k, v in expected.items()) or "externalRefs" in package:
        raise ValueError("native advisory SBOM native package differs from SOURCE")
    wrapper = descriptor["wrapper"]
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    component = _cargo_registry_component({"name": wrapper["name"], "version": wrapper["version"], "source": registry},
                                          {(wrapper["name"], wrapper["version"], registry): wrapper["sha256"]})
    wrappers = [p for p in packages if p.get("name") == wrapper["name"]]
    wrapper_fields = {"SPDXID": component.spdx_id, "versionInfo": wrapper["version"],
                      "downloadLocation": component.download_location,
                      "checksums": [{"algorithm": "SHA256", "checksumValue": wrapper["sha256"]}],
                      "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component.purl}]}
    if len(wrappers) != 1 or any(wrappers[0].get(k) != v for k, v in wrapper_fields.items()):
        raise ValueError("native advisory SBOM registry wrapper is not genuine")
    expected_edges, sha1s, native_file_ids = [], [], set()
    for item in descriptor["files"]:
        payload = read_snapshot(root / native.TARGETS[0] / "include" / item["path"], native.MAX_FILE_BYTES)
        if len(payload) != item["size"] or build.sha(payload) != item["sha256"]:
            raise ValueError("native advisory proved C/header changed")
        relative = descriptor["path"] + "/" + item["path"]
        file_id = "SPDXRef-File-" + build.sha((descriptor_hash + "\0" + relative).encode())
        native_file_ids.add(file_id)
        sha1 = hashlib.sha1(payload).hexdigest()
        sha1s.append(sha1)
        matches = [f for f in files if f["SPDXID"] == file_id]
        checksums = [{"algorithm": "SHA1", "checksumValue": sha1}, {"algorithm": "SHA256", "checksumValue": item["sha256"]}]
        if len(matches) != 1 or matches[0].get("fileName") != "./" + relative or matches[0].get("checksums") != checksums:
            raise ValueError("native advisory SBOM C/header file differs")
        expected_edges.append({"spdxElementId": package_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_id})
    verification = {"packageVerificationCodeValue": hashlib.sha1("".join(sorted(sha1s)).encode("ascii")).hexdigest()}
    if package.get("packageVerificationCode") != verification:
        raise ValueError("native advisory SBOM native file inventory checksum differs")
    declared_native_files = {f["SPDXID"] for f in files if isinstance(f.get("fileName"), str)
                             and f["fileName"].startswith("./" + descriptor["path"] + "/")}
    if declared_native_files != native_file_ids:
        raise ValueError("native advisory SBOM native file inventory has extras")
    expected_edges.append({"spdxElementId": component.spdx_id, "relationshipType": "STATIC_LINK", "relatedSpdxElement": package_id})
    if not any(p["SPDXID"] == "SPDXRef-Package-geph5-client" for p in packages):
        raise ValueError("native advisory SBOM lacks its Geph root package")
    expected_edges.append({"spdxElementId": "SPDXRef-Package-geph5-client", "relationshipType": "CONTAINS", "relatedSpdxElement": package_id})
    edges = [r for r in relationships if isinstance(r, dict) and package_id in (r.get("spdxElementId"), r.get("relatedSpdxElement"))
             and r.get("relationshipType") in {"CONTAINS", "STATIC_LINK", "DYNAMIC_LINK"}]
    if sorted(edges, key=canonical) != sorted(expected_edges, key=canonical):
        raise ValueError("native advisory SBOM native linkage/file relationships differ")
    return package_id


def _validate_native_review(review: dict, *, sbom: dict, source_path: Path,
                           native_receipt: Path, native_artifacts_root: Path,
                           evaluated_on: date, evidence_root: Path | None = None,
                           verification_on: date | None = None) -> dict:
    """Return deterministic coverage; malformed/stale inputs raise, unknowns fail."""
    # Copy policy/SBOM structures once; no callbacks or caller-owned mutable state.
    review, sbom = _json(canonical(review)), _json(canonical(sbom))
    current = datetime.now(timezone.utc).date() if verification_on is None else verification_on
    records, groups = _review_schema(review, evaluated_on, current)
    source_bytes = read_snapshot(Path(source_path), vendor.MAX_SOURCE_BYTES)
    source = _json(source_bytes)
    vendor._validate_source_contract(source)
    if "native_sqlite" not in source:
        raise ValueError("native advisory review requires native SOURCE")
    descriptor, source_hash = source["native_sqlite"], build.sha(source_bytes)
    root = build._root(Path(native_artifacts_root))
    proof = build.verify_release_evidence(descriptor, Path(native_receipt), root, source_hash, source["lock_sha256"])
    binding = {"source_sha256": source_hash, "descriptor_sha256": native.descriptor_sha256(descriptor),
               "version": descriptor["version"], "source_id": descriptor["source_id"],
               "archive_sha256": descriptor["archive"]["sha256"],
               "files": {item["path"]: item["sha256"] for item in descriptor["files"]},
               "targets": descriptor["targets"], "compile_definitions": descriptor["compile_definitions"],
               "native_receipt_sha256": proof["receipt_sha256"], "final_binary_sha256": proof["final_binary_sha256"]}
    if review["binding"] != binding:
        raise ValueError("native advisory review binding differs from independently verified SOURCE/proof")
    package_id = _native_sbom(sbom, descriptor, source_hash, proof, root)
    if evidence_root is not None:
        evidence_root = build._root(Path(evidence_root))
        payloads = {identity: _evidence_bytes(evidence_root, record) for identity, record in records.items()}
        _verify_census(review, payloads)
    native_groups = [g for g in groups if g["identity"] == "native"]
    clear = [g for g in native_groups if g["review_status"] == "adjudicated"
             and g["decision"] in {"code_fixed", "code_not_present", "rejected"}]
    summary = {"groups_total": len(groups), "native_groups": len(native_groups),
               "excluded_groups": len(groups) - len(native_groups), "adjudicated_not_affected": len(clear),
               "unknown": sum(g["decision"] == "unknown" for g in native_groups),
               "affected": sum(g["decision"] == "affected" for g in native_groups),
               "census_only": sum(g["review_status"] == "census_only" and g["decision"] != "unknown" for g in native_groups),
               "unresolved": len(native_groups) - len(clear)}
    decisions = [{k: g[k] for k in ("id", "aliases", "identity", "census_verdict", "decision", "review_status", "source_verdict")}
                 for g in groups]
    return {"schema_version": 1, "package_id": package_id, "review_sha256": build.sha(canonical(review)),
            "binding": binding, "census": review["census"], "decisions": decisions,
            "summary": summary, "status": "pass" if not summary["unresolved"] else "fail"}


def validate_native_review(review: dict, *, sbom: dict, source_path: Path,
                           native_receipt: Path, native_artifacts_root: Path,
                           evaluated_on: date, evidence_root: Path | None = None,
                           verification_on: date | None = None) -> dict:
    """Validate reviewed schema and evidence, with ValueError for malformed data.

    verification_on is an injectable trusted clock for callers' deterministic
    tests; release entrypoints omit it and use the current UTC date.
    """
    try:
        return _validate_native_review(review, sbom=sbom, source_path=source_path,
            native_receipt=native_receipt, native_artifacts_root=native_artifacts_root,
            evaluated_on=evaluated_on, evidence_root=evidence_root, verification_on=verification_on)
    except (KeyError, TypeError, UnicodeError, OverflowError) as exc:
        raise ValueError("native advisory schema or retained evidence is malformed") from exc

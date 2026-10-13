#!/usr/bin/env python3
"""Owned SQLite static inputs and linked-target evidence; never a release waiver.

Native receipts prove only the compiled archive. Linked receipts additionally
bind the sys rlib, its native member, the linker map and one unstripped Mach-O
slice. A universal/stripped release must be bound by a separate final producer
and consumer check. These are coherence checks, not substitutes for attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess

import geph_native_sqlite as native

TARGET_ARCH = {"aarch64-apple-darwin": ("arm64", 0x0100000C),
               "x86_64-apple-darwin": ("x86_64", 0x01000007)}
MAX_BYTES = 512 * 1024 * 1024
NATIVE_SCOPE = "owned-native-archive-only"
LINKED_SCOPE = "unstripped-geph-target-slice"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{label}: unexpected schema")


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid SHA256")


def _root(path: Path) -> Path:
    path = Path(path).absolute()
    if path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError("artifact root must be a physical directory")
    return path


def _path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("artifact path must be a string")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or str(parts) != relative or any(x in (".", "..") for x in parts.parts):
        raise ValueError("artifact path must be canonical and relative")
    path = root / relative
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("artifact must be a physical regular file")
    return path


def _read(path: Path, limit=MAX_BYTES) -> bytes:
    return native.read_regular(Path(path), limit)


def _record(root: Path, path: Path) -> dict:
    payload = _read(path)
    return {"path": str(path.relative_to(root)), "size": len(payload), "sha256": sha(payload)}


def _bound(root: Path, record: dict, limit=MAX_BYTES) -> bytes:
    _keys(record, ("path", "size", "sha256"), "artifact")
    _digest(record["sha256"])
    if type(record["size"]) is not int or not 0 < record["size"] <= limit:
        raise ValueError("artifact size is invalid")
    payload = _read(_path(root, record["path"]), limit)
    if len(payload) != record["size"] or sha(payload) != record["sha256"]:
        raise ValueError("artifact hash/size mismatch")
    return payload


def _json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON evidence") from exc


def archive_members(payload: bytes) -> dict[str, bytes]:
    """Read bounded BSD/GNU ar without extraction or tool/path interpretation."""
    if not payload.startswith(b"!<arch>\n"):
        raise ValueError("not a static ar archive")
    offset, members, names = 8, {}, b""
    while offset < len(payload):
        header = payload[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("invalid ar header")
        try:
            size = int(header[48:58].strip())
            name = header[:16].decode("ascii").strip()
        except (ValueError, UnicodeError) as exc:
            raise ValueError("invalid ar member") from exc
        start, end = offset + 60, offset + 60 + size
        if size < 0 or end > len(payload):
            raise ValueError("invalid ar member size")
        data = payload[start:end]
        if name.startswith("#1/"):
            try:
                count = int(name[3:])
                if count <= 0 or count > len(data):
                    raise ValueError()
                name = data[:count].rstrip(b"\0").decode("ascii")
            except (ValueError, UnicodeError) as exc:
                raise ValueError("invalid BSD ar name") from exc
            data = data[count:]
        elif name == "//":
            names = data
        elif name.startswith("/") and name[1:].isdigit():
            index = int(name[1:])
            stop = names.find(b"/\n", index)
            if index >= len(names) or stop < 0:
                raise ValueError("invalid GNU ar name")
            name = names[index:stop].decode("ascii")
        else:
            name = name.rstrip("/")
        if name and name not in ("/", "//") and not name.startswith("__.SYMDEF"):
            if name in members or "/" in name or "\\" in name or name in (".", ".."):
                raise ValueError("duplicate/unsafe ar member")
            members[name] = data
        offset = end + (size % 2)
        if offset > len(payload):
            raise ValueError("truncated ar padding")
    return members


def macho(payload: bytes, target: str, *, executable=False) -> dict:
    if target not in TARGET_ARCH or len(payload) < 32:
        raise ValueError("unsupported target/Mach-O")
    header = struct.unpack_from("<8I", payload)
    magic, cpu, _, kind, count, size, _, _ = header
    if magic != 0xFEEDFACF or cpu != TARGET_ARCH[target][1] or kind != (2 if executable else 1):
        raise ValueError("Mach-O architecture/type mismatch")
    if count > 4096 or size > len(payload) - 32:
        raise ValueError("invalid Mach-O load commands")
    offset, end, dylibs, symbols = 32, 32 + size, [], {}
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("truncated Mach-O command")
        command, length = struct.unpack_from("<II", payload, offset)
        if length < 8 or offset + length > end:
            raise ValueError("invalid Mach-O command size")
        if command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            if length < 24:
                raise ValueError("truncated dylib command")
            nameoff = struct.unpack_from("<I", payload, offset + 8)[0]
            if not 24 <= nameoff < length:
                raise ValueError("invalid dylib name")
            raw = payload[offset + nameoff:offset + length]
            if b"\0" not in raw:
                raise ValueError("unterminated dylib name")
            dylibs.append(raw.split(b"\0", 1)[0].decode("utf-8"))
        if command == 2:
            if length != 24:
                raise ValueError("invalid symtab command")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", payload, offset + 8)
            if symoff + nsyms * 16 > len(payload) or stroff + strsize > len(payload):
                raise ValueError("invalid Mach-O symbol bounds")
            strings = payload[stroff:stroff + strsize]
            for idx in range(nsyms):
                string, typ, section, _, address = struct.unpack_from("<IBBHQ", payload, symoff + 16 * idx)
                if string >= len(strings):
                    raise ValueError("invalid Mach-O string index")
                stop = strings.find(b"\0", string)
                if stop < 0:
                    raise ValueError("unterminated Mach-O symbol")
                if not typ & 0xE0 and typ & 0x0E == 0x0E and section:
                    name = strings[string:stop].decode("ascii")
                    # Rust emits repeated local names in different codegen
                    # units. Only the two global identity symbols must be
                    # unambiguous for our linker-map comparison.
                    if name in ("_sqlite3_libversion", "_sqlite3_sourceid"):
                        if not typ & 1:
                            raise ValueError("SQLite identity symbol must be global")
                        if name in symbols:
                            raise ValueError("duplicate SQLite identity symbol")
                        symbols[name] = address
        offset += length
    if offset != end:
        raise ValueError("unconsumed Mach-O commands")
    if any("sqlite" in name.lower() for name in dylibs):
        raise ValueError("host/dynamic SQLite dependency is forbidden")
    if executable and not {"_sqlite3_libversion", "_sqlite3_sourceid"} <= symbols.keys():
        raise ValueError("final slice lacks defined SQLite identity symbols")
    return {"arch": TARGET_ARCH[target][0], "dylibs": dylibs,
            "sqlite_identity_symbols_defined": executable,
            "sqlite_identity_addresses": {name: symbols[name] for name in ("_sqlite3_libversion", "_sqlite3_sourceid") if name in symbols}}


def validate_feature_closure(metadata: dict, descriptor: dict) -> dict:
    native.validate_descriptor(descriptor)
    wanted = {"sqlx": ("0.8.6", "sqlite-unbundled"), "sqlx-sqlite": ("0.8.6", "unbundled"),
              "libsqlite3-sys": (descriptor["wrapper"]["version"], "buildtime_bindgen")}
    packages = metadata.get("packages", [])
    nodes = (metadata.get("resolve") or {}).get("nodes", [])
    result = {}
    for name, (version, required) in wanted.items():
        matches = [item for item in packages if item.get("name") == name]
        if len(matches) != 1 or matches[0].get("version") != version:
            raise ValueError(f"unexpected resolved {name} identity")
        package = matches[0]
        if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError(f"{name} must use the reviewed registry package")
        matched_nodes = [item for item in nodes if item.get("id") == package.get("id")]
        if len(matched_nodes) != 1:
            raise ValueError(f"missing/duplicate resolved {name} node")
        features = matched_nodes[0].get("features")
        if not isinstance(features, list) or any(not isinstance(f, str) for f in features):
            raise ValueError("invalid resolved feature list")
        if required not in features or any(any(bad in f for bad in ("bundled", "sqlcipher", "loadable", "in_gecko", "in-gecko")) and f not in ("unbundled", "sqlite-unbundled") for f in features):
            raise ValueError(f"unsafe resolved {name} features")
        if name == "sqlx" and "sqlite" in features:
            raise ValueError("SQLx sqlite feature reenables bundled SQLite")
        result[name] = sorted(features)
    return result


def _tool(path: Path) -> dict:
    path = Path(path).absolute()
    data = _read(path)
    if not os.access(path, os.X_OK):
        raise ValueError("compiler/archiver is not executable")
    return {"path": str(path), "size": len(data), "sha256": sha(data)}


def _commands(descriptor, target, directory, tools):
    arch = TARGET_ARCH[target][0]
    return [[tools["clang"]["path"], "-O2", "-fPIC", "-arch", arch,
             "-isysroot", tools["sdk"]["path"], "-mmacosx-version-min=11.0",
             *["-D" + item for item in descriptor["compile_definitions"]],
             "-c", str(directory / "include/sqlite3.c"), "-o", str(directory / "sqlite3.o")],
            [tools["ar"]["path"], "rcs", str(directory / "libsqlite3.a"), str(directory / "sqlite3.o")]]


def build_native(descriptor: dict, source_root: Path, output_root: Path, target: str,
                 source_sha256: str, lock_path: Path, tools: dict) -> dict:
    """Snapshot checked source; build once in a fresh per-target directory."""
    native.validate_descriptor(descriptor)
    _digest(source_sha256)
    if target not in descriptor["targets"]:
        raise ValueError("unreviewed target")
    contents = native.verify_materialized(descriptor, source_root)
    root = _root(output_root)
    lock = _read(lock_path, 64 * 1024 * 1024)
    _keys(tools, ("clang", "ar", "sdk"), "build tools")
    sdk = _root(Path(tools["sdk"]))
    settings = _read(sdk / "SDKSettings.json", 1024 * 1024)
    tool_records = {name: _tool(Path(tools[name])) for name in ("clang", "ar")}
    tool_records["sdk"] = {"path": str(sdk), "settings_sha256": sha(settings)}
    directory = root / target
    directory.mkdir()  # Existing output, symlinks and stale objects fail closed.
    (directory / "include").mkdir()
    (directory / "tmp").mkdir()
    for name, data in contents.items():
        (directory / "include" / name).write_bytes(data)
    commands = _commands(descriptor, target, directory, tool_records)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(directory / "tmp")}
    for index, command in enumerate(commands):
        with (directory / f"command-{index}.log").open("xb") as log:
            subprocess.run(command, env=env, cwd=directory, stdout=log, stderr=subprocess.STDOUT,
                           timeout=180, check=True)
    if tool_records != {**{name: _tool(Path(tools[name])) for name in ("clang", "ar")},
                        "sdk": {"path": str(sdk), "settings_sha256": sha(_read(sdk / "SDKSettings.json", 1024 * 1024))}}:
        raise ValueError("toolchain changed during native build")
    receipt = {"schema_version": 1, "scope": NATIVE_SCOPE, "target": target,
               "descriptor_sha256": native.descriptor_sha256(descriptor), "source_sha256": source_sha256,
               "lock_sha256": sha(lock), "helper_sha256": sha(_read(Path(__file__).resolve())),
               "tools": tool_records, "commands": commands,
               "environment": env, "build_directory": str(directory),
               "files": {name: _record(root, directory / name) for name in
                         ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a")}}
    path = directory / "native-build.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return verify_native_build(descriptor, path, root, source_sha256, sha(lock))


def verify_native_build(descriptor: dict, receipt_path: Path, artifacts_root: Path,
                        source_sha256: str, lock_sha256: str) -> dict:
    native.validate_descriptor(descriptor)
    root = _root(artifacts_root)
    payload = _read(_path(root, str(Path(receipt_path).absolute().relative_to(root))), 1024 * 1024)
    receipt = _json(payload)
    _keys(receipt, ("schema_version", "scope", "target", "descriptor_sha256", "source_sha256", "lock_sha256",
                    "helper_sha256", "tools", "commands", "environment", "build_directory", "files"), "native receipt")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["scope"] != NATIVE_SCOPE:
        raise ValueError("not a native archive receipt")
    for name, expected in (("descriptor_sha256", native.descriptor_sha256(descriptor)),
                           ("source_sha256", source_sha256), ("lock_sha256", lock_sha256),
                           ("helper_sha256", sha(_read(Path(__file__).resolve())))):
        _digest(expected)
        if receipt[name] != expected:
            raise ValueError(f"native receipt {name} mismatch")
    target = receipt["target"]
    if target not in descriptor["targets"]:
        raise ValueError("native receipt target mismatch")
    _keys(receipt["tools"], ("clang", "ar", "sdk"), "tools")
    for name in ("clang", "ar"):
        item = receipt["tools"][name]
        _keys(item, ("path", "size", "sha256"), "tool")
        _digest(item["sha256"])
        if not isinstance(item["path"], str) or not Path(item["path"]).is_absolute() or type(item["size"]) is not int or item["size"] <= 0:
            raise ValueError("invalid tool identity")
    sdk = receipt["tools"]["sdk"]
    _keys(sdk, ("path", "settings_sha256"), "SDK")
    _digest(sdk["settings_sha256"])
    if not isinstance(sdk["path"], str) or not Path(sdk["path"]).is_absolute():
        raise ValueError("invalid SDK identity")
    directory = Path(receipt["build_directory"])
    if not directory.is_absolute() or directory.name != target:
        raise ValueError("invalid native build directory")
    if receipt["commands"] != _commands(descriptor, target, directory, receipt["tools"]):
        raise ValueError("native compiler/archive arguments mismatch")
    if receipt["environment"] != {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(directory / "tmp")}:
        raise ValueError("native build environment mismatch")
    files = receipt["files"]
    _keys(files, ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a"), "native files")
    data = {name: _bound(root, item) for name, item in files.items()}
    if any(item["path"] != f"{target}/{name}" for name, item in files.items()):
        raise ValueError("native files do not belong to their target directory")
    for entry in descriptor["files"]:
        source = data["include/" + entry["path"]]
        if len(source) != entry["size"] or sha(source) != entry["sha256"]:
            raise ValueError("native build used wrong C/header")
    macho(data["sqlite3.o"], target)
    if archive_members(data["libsqlite3.a"]) != {"sqlite3.o": data["sqlite3.o"]}:
        raise ValueError("static archive differs from owned object")
    return {**receipt, "receipt_sha256": sha(payload)}


def cargo_environment(descriptor: dict, receipt_path: Path, artifacts_root: Path,
                      source_sha256: str, lock_sha256: str, inherited: dict | None = None) -> dict:
    """Sanitize native/search overrides; caller must also validate Cargo metadata.

This is preparation, not proof of what an arbitrary executable finally linked.
The linked-target verifier requires the actual rlib and linker map.
"""
    proof = verify_native_build(descriptor, receipt_path, artifacts_root, source_sha256, lock_sha256)
    bad = ("CARGO_", "RUST", "SQLITE", "SQLCIPHER", "LIBSQLITE", "BINDGEN", "PKG_CONFIG", "DYLD_",
           "LIBCLANG", "CFLAGS", "CPPFLAGS", "LDFLAGS", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "CC", "CXX", "AR", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "VCPKG", "LD_PRELOAD")
    env = {key: value for key, value in (os.environ if inherited is None else inherited).items() if not key.startswith(bad)}
    root = _root(artifacts_root)
    include = _path(root, proof["files"]["include/sqlite3.h"]["path"]).parent
    library = _path(root, proof["files"]["libsqlite3.a"]["path"]).parent
    env.update(SQLITE3_INCLUDE_DIR=str(include), SQLITE3_LIB_DIR=str(library), SQLITE3_STATIC="1", SQLITE3_NO_PKG_CONFIG="1",
               SDKROOT=proof["tools"]["sdk"]["path"], MACOSX_DEPLOYMENT_TARGET="11.0",
               CC=proof["tools"]["clang"]["path"], AR=proof["tools"]["ar"]["path"])
    return env


def _link_evidence(native_proof: dict, root: Path, files: dict, binary_build_path: str, rlib_build_path: str, descriptor: dict) -> dict:
    _keys(files, ("sys_build_output", "rlib", "link_map", "binary", "cargo_metadata"), "linked files")
    data = {name: _bound(root, item) for name, item in files.items()}
    validate_feature_closure(_json(data["cargo_metadata"]), descriptor)
    owned = _bound(root, native_proof["files"]["sqlite3.o"])
    members = archive_members(data["rlib"])
    if members.get("sqlite3.o") != owned:
        raise ValueError("sys rlib does not contain exact owned SQLite object")
    rust_objects = [payload for name, payload in members.items() if name.endswith(".rcgu.o")]
    if not members.get("lib.rmeta") or not rust_objects:
        raise ValueError("sys input is not a Rust rlib with metadata and codegen objects")
    for obj in rust_objects:
        macho(obj, native_proof["target"])
    # Reject additional native SQLite objects rather than merely finding one.
    if any("sqlite" in name.lower() and name.endswith(".o") and name != "sqlite3.o" and not name.endswith(".rcgu.o") for name in members):
        raise ValueError("sys rlib contains unexpected SQLite objects")
    output = data["sys_build_output"].decode("utf-8")
    directives = [line.removeprefix("cargo::").removeprefix("cargo:") for line in output.splitlines() if line.startswith(("cargo:", "cargo::"))]
    links = [line for line in directives if line.startswith("rustc-link-")]
    links = [line.replace("rustc-link-search=native=", "rustc-link-search=", 1) for line in links]
    directory = Path(native_proof["build_directory"])
    if sorted(links) != sorted(["rustc-link-lib=static=sqlite3", "rustc-link-search=" + str(directory)]):
        raise ValueError("sys build requested unexpected linker input/search path")
    text = data["link_map"].decode("utf-8")
    if not isinstance(binary_build_path, str) or not Path(binary_build_path).is_absolute() or not isinstance(rlib_build_path, str) or not Path(rlib_build_path).is_absolute():
        raise ValueError("link build paths must be absolute")
    if text.splitlines().count("# Path: " + binary_build_path) != 1:
        raise ValueError("link map does not identify target binary")
    if text.splitlines().count("# Arch: " + TARGET_ARCH[native_proof["target"]][0]) != 1:
        raise ValueError("link map architecture mismatch")
    object_rows = re.findall(r"^\[\s*(\d+)\]\s+(.+)$", text, re.MULTILINE)
    # Apple ld-1053 emits archive[index](member); ld-1267 emits
    # archive(member). Only this observed numeric annotation is optional:
    # both forms must still name the exact absolute archive and native member.
    member = re.compile(re.escape(rlib_build_path) + r"(?:\[[0-9]+\])?\(sqlite3\.o\)")
    matches = [index for index, name in object_rows if member.fullmatch(name)]
    duplicate_indices = len({int(idx) for idx, _ in object_rows}) != len(object_rows)
    if len(matches) != 1 or duplicate_indices:
        # Keep the decisive input in CI failures: supported Apple linkers can
        # evolve their display grammar independently of the linked bytes. Do
        # not silently normalize an unobserved spelling or accept a basename.
        relevant = [(idx, name[:1024]) for idx, name in object_rows
                    if ".rlib" in name or "sqlite3" in name]
        detail = {"expected": (rlib_build_path + "(sqlite3.o)")[:1024],
                  "matches": len(matches), "object_rows": len(object_rows),
                  "duplicate_indices": duplicate_indices,
                  "relevant_rows": (relevant or object_rows)[:8]}
        raise ValueError("link map must use the exact sys rlib native member once: " + json.dumps(detail, sort_keys=True))
    try:
        live = text.split("# Symbols:\n", 1)[1].split("# Dead Stripped Symbols:", 1)[0]
    except IndexError as exc:
        raise ValueError("missing live linker symbols") from exc
    identity = macho(data["binary"], native_proof["target"], executable=True)
    if descriptor["source_id"].encode() + b"\0" not in data["binary"] or descriptor["version"].encode() + b"\0" not in data["binary"]:
        raise ValueError("linked binary lacks exact SQLite version/source ID")
    for symbol in ("_sqlite3_libversion", "_sqlite3_sourceid"):
        rows = re.findall(r"^(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+\[\s*" + re.escape(matches[0]) + r"\]\s+" + symbol + r"\s*$", live, re.MULTILINE)
        if len(rows) != 1 or int(rows[0][1], 16) <= 0:
            raise ValueError("SQLite identity symbol not provided by owned link member")
        if int(rows[0][0], 16) != identity["sqlite_identity_addresses"][symbol]:
            raise ValueError("link map symbol address differs from actual binary")
    return identity


def seal_linked_target(descriptor: dict, native_receipt_path: Path, artifacts_root: Path,
                       source_sha256: str, lock_sha256: str, files: dict[str, Path],
                       binary_build_path: str, rlib_build_path: str, receipt_path: Path) -> dict:
    root = _root(artifacts_root)
    native_proof = verify_native_build(descriptor, native_receipt_path, root, source_sha256, lock_sha256)
    records = {name: _record(root, Path(path)) for name, path in files.items()}
    _link_evidence(native_proof, root, records, binary_build_path, rlib_build_path, descriptor)
    receipt = {"schema_version": 1, "scope": LINKED_SCOPE, "target": native_proof["target"],
               "source_sha256": source_sha256, "lock_sha256": lock_sha256,
               "descriptor_sha256": native.descriptor_sha256(descriptor),
               "native_receipt": _record(root, Path(native_receipt_path)), "files": records,
               "binary_build_path": binary_build_path, "rlib_build_path": rlib_build_path}
    path = Path(receipt_path)
    if path.parent.resolve(strict=True) != path.parent or path.parent != root or path.exists():
        raise ValueError("linked receipt must be a fresh file in artifact root")
    with path.open("x") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return verify_linked_target(descriptor, path, root, source_sha256, lock_sha256)


def verify_linked_target(descriptor: dict, receipt_path: Path, artifacts_root: Path,
                         source_sha256: str, lock_sha256: str) -> dict:
    native.validate_descriptor(descriptor)
    root = _root(artifacts_root)
    payload = _read(_path(root, str(Path(receipt_path).absolute().relative_to(root))), 1024 * 1024)
    receipt = _json(payload)
    _keys(receipt, ("schema_version", "scope", "target", "source_sha256", "lock_sha256", "descriptor_sha256",
                    "native_receipt", "files", "binary_build_path", "rlib_build_path"), "linked receipt")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["scope"] != LINKED_SCOPE:
        raise ValueError("linked Geph slice evidence required; native archive alone is insufficient")
    for key, expected in (("source_sha256", source_sha256), ("lock_sha256", lock_sha256),
                          ("descriptor_sha256", native.descriptor_sha256(descriptor))):
        _digest(expected)
        if receipt[key] != expected:
            raise ValueError("linked receipt input identity mismatch")
    _bound(root, receipt["native_receipt"], 1024 * 1024)
    proof = verify_native_build(descriptor, _path(root, receipt["native_receipt"]["path"]), root, source_sha256, lock_sha256)
    if proof["target"] != receipt["target"]:
        raise ValueError("linked target differs from native target")
    identity = _link_evidence(proof, root, receipt["files"], receipt["binary_build_path"], receipt["rlib_build_path"], descriptor)
    return {**receipt, "receipt_sha256": sha(payload), "native_receipt_sha256": proof["receipt_sha256"], "identity": identity}



def universal_slices(payload: bytes) -> dict[str, bytes]:
    """Accept only two reviewed, non-overlapping, aligned Mach-O slices."""
    if len(payload) < 8 or payload[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        raise ValueError("expected universal Mach-O")
    wide = payload[:4] == b"\xca\xfe\xba\xbf"
    count = struct.unpack_from(">I", payload, 4)[0]
    entry_size = 32 if wide else 20
    if count != 2 or len(payload) < 8 + count * entry_size:
        raise ValueError("universal binary must contain exactly two targets")
    result, spans = {}, []
    for idx in range(count):
        entry = struct.unpack_from(">IIQQII" if wide else ">IIIII", payload, 8 + idx * entry_size)
        cpu, _, offset, size, alignment = entry[:5]
        targets = [target for target, (_, expected_cpu) in TARGET_ARCH.items() if cpu == expected_cpu]
        if len(targets) != 1 or targets[0] in result or (wide and entry[5] != 0):
            raise ValueError("unexpected/duplicate universal architecture")
        if alignment > 30 or offset % (1 << alignment) or offset < 8 + count * entry_size or size < 32 or offset + size > len(payload):
            raise ValueError("invalid universal slice bounds/alignment")
        if any(offset < end and offset + size > start for start, end in spans):
            raise ValueError("overlapping universal slices")
        target = targets[0]
        result[target] = payload[offset:offset + size]
        macho(result[target], target, executable=True)
        spans.append((offset, offset + size))
    previous = 8 + count * entry_size
    for start, end in sorted(spans):
        if any(payload[previous:start]):
            raise ValueError("unexpected bytes in universal padding")
        previous = end
    if previous != len(payload):
        raise ValueError("unexpected universal trailing bytes")
    return result


def verify_release_evidence(descriptor: dict, receipt_path: Path, artifacts_root: Path,
                            source_sha256: str, lock_sha256: str) -> dict:
    """Bind the final universal bytes to exact independently proved target slices.

    Post-proof stripping/signing invalidates hashes. Producer and consumer must
    prove the actual published artifact. Coherence does not replace attestation.
    """
    native.validate_descriptor(descriptor)
    root = _root(artifacts_root)
    payload = _read(_path(root, str(Path(receipt_path).absolute().relative_to(root))), 1024 * 1024)
    receipt = _json(payload)
    _keys(receipt, ("schema_version", "scope", "source_sha256", "lock_sha256", "descriptor_sha256",
                    "targets", "linked_receipts", "final_binary"), "release native evidence")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["scope"] != "linked-macos-universal":
        raise ValueError("final universal link proof required")
    for key, expected in (("source_sha256", source_sha256), ("lock_sha256", lock_sha256),
                          ("descriptor_sha256", native.descriptor_sha256(descriptor))):
        _digest(expected)
        if receipt[key] != expected:
            raise ValueError("final native evidence input mismatch")
    if receipt["targets"] != descriptor["targets"]:
        raise ValueError("final native evidence target mismatch")
    _keys(receipt["linked_receipts"], descriptor["targets"], "per-target receipts")
    slices = universal_slices(_bound(root, receipt["final_binary"]))
    for target, record in receipt["linked_receipts"].items():
        _bound(root, record, 1024 * 1024)
        proof = verify_linked_target(descriptor, _path(root, record["path"]), root, source_sha256, lock_sha256)
        if proof["target"] != target or slices[target] != _bound(root, proof["files"]["binary"]):
            raise ValueError("final universal slice differs from linked/proved target")
    return {**receipt, "receipt_sha256": sha(payload), "final_binary_sha256": receipt["final_binary"]["sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--target", choices=TARGET_ARCH, required=True)
    for tool in ("clang", "ar", "sdk"):
        parser.add_argument("--" + tool, type=Path, required=True)
    args = parser.parse_args()
    source = _read(args.source, 4 * 1024 * 1024)
    descriptor = _json(source)["native_sqlite"]
    result = build_native(descriptor, args.source_root, args.output_root, args.target, sha(source), args.lock,
                          {tool: getattr(args, tool) for tool in ("clang", "ar", "sdk")})
    print(json.dumps({"scope": result["scope"], "target": result["target"], "receipt_sha256": result["receipt_sha256"]}))


if __name__ == "__main__":
    main()

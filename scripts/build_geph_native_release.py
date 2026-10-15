#!/usr/bin/env python3
"""Inactive, offline producer for an unstripped, source-bound Geph universal binary.

No upstream tests or produced binaries are executed. Inputs and dependency caches
must already exist locally. This is build/link evidence, not release approval,
account qualification, native advisory coverage or an installed-app E2E test.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

import geph_native_sqlite as native
import geph_native_sqlite_build as link
import geph_vendor_source as vendor

MAX_LOG = 64 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024


def write_json(path: Path, value: dict) -> None:
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run(command: list[str], *, cwd: Path, env: dict, prefix: Path,
        timeout: float, stdout_limit: int = MAX_LOG) -> None:
    """Keep stdout machine-readable; retain stderr and reap the entire owned group."""
    if not math.isfinite(timeout) or not 0 < timeout <= 7200:
        raise ValueError("command timeout must be positive and at most two hours")
    if type(stdout_limit) is not int or not 0 < stdout_limit <= MAX_LOG:
        raise ValueError("invalid stdout limit")
    started = time.monotonic()
    stdout, stderr = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
    reason = None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err,
                                   start_new_session=True)
        try:
            while True:
                if stdout.stat().st_size > stdout_limit or stderr.stat().st_size > MAX_METADATA:
                    reason = "output limit exceeded"
                    break
                if time.monotonic() - started > timeout:
                    reason = "timeout"
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.05)
        finally:
            # A successful launcher can still leave a build-script child alive.
            # Reap an already-exited launcher before killpg: macOS can return
            # EPERM for a zombie-only group instead of ESRCH.
            process.poll()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = process.wait(timeout=5)
            sizes = {"stdout": stdout.stat().st_size, "stderr": stderr.stat().st_size}
            if sizes["stdout"] > stdout_limit or sizes["stderr"] > MAX_METADATA:
                reason = "output limit exceeded"
                for path, limit in ((stdout, stdout_limit), (stderr, MAX_METADATA)):
                    if path.stat().st_size > limit:
                        with path.open("r+b") as stream:
                            stream.truncate(limit)
            write_json(prefix.with_suffix(".json"), {
                "command": command, "cwd": str(cwd), "environment": env,
                "returncode": code, "failure": reason,
                "original_log_bytes": sizes,
                "elapsed_seconds": time.monotonic() - started,
            })
    if reason or code:
        raise RuntimeError(f"build command failed: {reason or code}; see {prefix}")


def inside(root: Path, value: str, *, directory=False) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("Cargo artifact path must be absolute")
    path = Path(value)
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise ValueError("Cargo artifact escapes physical owned directory")
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError("Cargo artifact has wrong type")
    return path


def no_cargo_config(cwd: Path, cargo_home: Path) -> None:
    # --offline does not disable Cargo configuration (including rustc wrappers).
    candidates = [cargo_home / name for name in ("config", "config.toml")]
    candidates += [parent / ".cargo" / name for parent in (cwd, *cwd.parents)
                   for name in ("config", "config.toml")]
    if any(path.exists() or path.is_symlink() for path in candidates):
        raise ValueError("ambient Cargo configuration is forbidden")


def source_inventory(root: Path) -> dict:
    result, size = {}, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            if (Path(directory) / name).is_symlink():
                raise ValueError("materialized source contains a symlink")
        for name in files:
            path = Path(directory) / name
            record = link._record(root, path)
            size += record["size"]
            result[record["path"]] = record
            if len(result) > 8192 or size > 192 * 1024 * 1024:
                raise ValueError("materialized source exceeds inventory bounds")
    return result


def package_ids(metadata: dict, source: dict, source_root: Path) -> tuple[str, str]:
    link.validate_feature_closure(metadata, source["native_sqlite"])
    packages = metadata.get("packages", [])
    root = [p for p in packages if p.get("name") == "geph5-client"]
    wrapper = [p for p in packages if p.get("name") == "libsqlite3-sys"]
    if (len(root) != 1 or root[0].get("version") != source["crate"]["version"]
            or root[0].get("source") is not None
            or root[0].get("manifest_path") != str(source_root / "Cargo.toml")
            or (metadata.get("resolve") or {}).get("root") != root[0].get("id")):
        raise ValueError("Cargo metadata has wrong Geph root identity")
    for p in packages:
        if p.get("source") is None:
            inside(source_root, p.get("manifest_path"))
    for package in (root[0], wrapper[0]):
        if not isinstance(package.get("id"), str) or not package["id"]:
            raise ValueError("Cargo package ID is missing")
    nodes = [node for node in metadata["resolve"]["nodes"] if node.get("id") == root[0]["id"]]
    if len(nodes) != 1 or not set(source["features"]) <= set(nodes[0].get("features", [])):
        raise ValueError("Cargo metadata lacks reviewed Geph features")
    return root[0]["id"], wrapper[0]["id"]


def cargo_artifacts(log_path: Path, metadata: dict, source: dict, source_root: Path,
                    target_root: Path, target: str) -> dict[str, Path]:
    root_id, wrapper_id = package_ids(metadata, source, source_root)
    messages = []
    for line in native.read_regular(log_path, MAX_LOG).splitlines():
        if len(line) > 4 * 1024 * 1024:
            raise ValueError("oversized Cargo JSON message")
        value = link._json(line)
        if not isinstance(value, dict):
            raise ValueError("Cargo output must contain JSON objects")
        messages.append(value)
        if len(messages) > 100000:
            raise ValueError("too many Cargo messages")
    finished = [m for m in messages if m.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True or messages[-1] != finished[0]:
        raise ValueError("Cargo build did not finish successfully exactly once")
    binaries, libraries, scripts = [], [], []
    for message in messages:
        package = message.get("package_id")
        if message.get("reason") == "compiler-artifact":
            info = message.get("target") or {}
            if package == root_id and info.get("name") == "geph5-client" and info.get("kind") == ["bin"]:
                if message.get("profile", {}).get("test") is not False:
                    raise ValueError("Geph artifact is a test executable")
                binaries.append(inside(target_root / target / "release", message.get("executable")))
            if package == wrapper_id and info.get("name") == "libsqlite3_sys" and info.get("kind") == ["lib"]:
                paths = message.get("filenames", [])
                rlibs = [p for p in paths if isinstance(p, str) and p.endswith(".rlib")]
                if len(rlibs) != 1:
                    raise ValueError("sys Cargo artifact must name one rlib")
                libraries.append(inside(target_root / target / "release" / "deps", rlibs[0]))
        elif message.get("reason") == "build-script-executed" and package == wrapper_id:
            out = inside(target_root / target / "release" / "build", message.get("out_dir"), directory=True)
            if out.name != "out" or not out.parent.name.startswith("libsqlite3-sys-"):
                raise ValueError("unexpected sys build output directory")
            scripts.append(inside(target_root, str(out.parent / "output")))
    if len(binaries) != 1 or len(libraries) != 1 or len(scripts) != 1:
        raise ValueError("missing/duplicate package-matched Cargo build evidence")
    return {"binary": binaries[0], "rlib": libraries[0], "sys_build_output": scripts[0]}


def map_binary(path: Path, cargo_binary: Path, release_root: Path) -> Path:
    # Apple ld emits arbitrary literal-string bytes in symbol rows. Only the
    # structural path is text; never decode unrelated symbol payloads.
    lines = native.read_regular(path, MAX_LOG).split(b"\n")
    paths = [line.removeprefix(b"# Path: ") for line in lines if line.startswith(b"# Path: ")]
    if len(paths) != 1:
        raise ValueError("link map must identify exactly one binary")
    linked = inside(release_root, paths[0].decode("utf-8"))
    if native.read_regular(linked, link.MAX_BYTES) != native.read_regular(cargo_binary, link.MAX_BYTES):
        raise ValueError("link map executable differs from Cargo executable")
    return linked


def build_release(*, source_path: Path, version_path: Path, lock_path: Path,
                  crate_path: Path, native_archive: Path, output: Path,
                  cargo_home: Path, tools: dict, timeout: float = 1800, jobs: int = 2) -> dict:
    """Materialize once, compile both reviewed targets, and seal unchanged lipo output."""
    if not math.isfinite(timeout) or not 0 < timeout <= 7200:
        raise ValueError("invalid build timeout")
    if type(jobs) is not int or not 1 <= jobs <= 64:
        raise ValueError("build jobs must be an integer between 1 and 64")
    output = Path(output).absolute()
    if output.parent.resolve(strict=True) != output.parent or "," in str(output):
        raise ValueError("output needs a physical parent and no linker-argument commas")
    cargo_home = link._root(cargo_home)
    required = {"cargo", "rustc", "python", "clang", "ar", "lipo", "sdk", "libclang"}
    if set(tools) not in (required, required | {"cmake"}):
        raise ValueError("explicit reviewed tool paths are required")
    if any(not Path(path).is_absolute() or Path(path).resolve(strict=True) != Path(path)
           for path in tools.values()):
        raise ValueError("tools must have absolute physical paths")
    identities = {name: link._tool(Path(value)) for name, value in tools.items()
                  if name not in ("sdk", "libclang")}
    sdk = link._root(Path(tools["sdk"]))
    libclang = Path(tools["libclang"])
    if libclang.name != "libclang.dylib":
        raise ValueError("explicit libclang.dylib is required")
    libclang_bytes = native.read_regular(libclang, link.MAX_BYTES)
    sdk_settings = native.read_regular(sdk / "SDKSettings.json", 1024 * 1024)
    no_cargo_config(output, cargo_home)
    # Freeze the authoritative SOURCE bytes before any output or compiler work.
    # Re-reading the caller's file for staging could race this pin preflight.
    source_bytes = native.read_regular(Path(source_path), vendor.MAX_SOURCE_BYTES)
    source = vendor._json_object(source_bytes, "Geph source contract")
    vendor._validate_source_contract(source)
    if "native_sqlite" not in source:
        raise ValueError("reviewed native SQLite SOURCE is required")
    link.require_producer_helper(source["native_sqlite"])
    output.mkdir(mode=0o700)  # Refuse reused, partial or symlink output.
    snapshots = output / "inputs"
    snapshots.mkdir()
    for name, path, limit in (("SOURCE.json", source_path, vendor.MAX_SOURCE_BYTES),
                              ("VERSION", version_path, 1024), ("Cargo.lock", lock_path, MAX_METADATA),
                              ("geph.crate", crate_path, vendor.MAX_CRATE_BYTES),
                              ("sqlite.zip", native_archive, native.MAX_ARCHIVE_BYTES)):
        (snapshots / name).write_bytes(source_bytes if name == "SOURCE.json"
                                      else native.read_regular(Path(path), limit))
    input_records = [link._record(output, path) for path in sorted(snapshots.iterdir())]
    source = vendor.load_source_contract(snapshots / "SOURCE.json")
    if "native_sqlite" not in source:
        raise ValueError("reviewed native SQLite SOURCE is required")
    descriptor, source_hash = source["native_sqlite"], link.sha((snapshots / "SOURCE.json").read_bytes())
    link.require_producer_helper(descriptor)
    source_root = vendor.materialize_source(source_path=snapshots / "SOURCE.json",
        version_path=snapshots / "VERSION", cargo_lock_path=snapshots / "Cargo.lock",
        crate_path=snapshots / "geph.crate", native_sqlite_archive=snapshots / "sqlite.zip",
        output=output / "source")
    no_cargo_config(source_root, cargo_home)
    inventory = source_inventory(source_root)
    write_json(output / "source-files.json", inventory)
    helpers = [Path(__file__).resolve(), Path(native.__file__).resolve(),
               Path(link.__file__).resolve(), Path(vendor.__file__).resolve()]
    helper_hashes = {str(path): link.sha(native.read_regular(path, MAX_METADATA)) for path in helpers}
    evidence, logs, home, tmp = [output / name for name in ("evidence", "logs", "home", "tmp")]
    for directory in (evidence, logs, home, tmp):
        directory.mkdir()
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp),
                   "LC_ALL": "C", "CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true",
                   "RUSTC": identities["rustc"]["path"], "ZERO_AR_DATE": "1"}
    linked_receipts, binaries = {}, []
    for target in source["targets"]:
        prefix = logs / (target + "-native")
        command = [identities["python"]["path"], "-E", "-s", str(Path(link.__file__).resolve()),
                   "--source", str(snapshots / "SOURCE.json"), "--lock", str(snapshots / "Cargo.lock"),
                   "--source-root", str(source_root), "--output-root", str(evidence), "--target", target]
        for tool in ("clang", "ar", "sdk"):
            command.extend(["--" + tool, str(tools[tool])])
        run(command, cwd=home, env=environment, prefix=prefix, timeout=min(timeout, 600))
        native_receipt = evidence / target / "native-build.json"
        env = link.cargo_environment(descriptor, native_receipt, evidence, source_hash,
                                     source["lock_sha256"], inherited=environment)
        # cargo_environment deliberately removes ambient Rust/Cargo overrides;
        # only these explicit producer-owned values are restored.
        env.update({key: environment[key] for key in ("CARGO_HOME", "CARGO_NET_OFFLINE", "RUSTC")})
        env["LIBCLANG_PATH"] = str(libclang.parent)
        env["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] = identities["clang"]["path"]
        if "cmake" in identities:
            env["CMAKE"] = identities["cmake"]["path"]
        target_root = output / (target + "-cargo")
        target_root.mkdir()
        env["CARGO_TARGET_DIR"] = str(target_root)
        common = ["--manifest-path", str(source_root / "Cargo.toml"), "--locked", "--offline",
                  "--features", ",".join(source["features"])]
        metadata_prefix = logs / (target + "-metadata")
        no_cargo_config(home, cargo_home)
        run([identities["cargo"]["path"], "metadata", *common, "--filter-platform", target,
             "--format-version", "1"], cwd=home, env=env, prefix=metadata_prefix,
            timeout=timeout, stdout_limit=MAX_METADATA)
        metadata_path = metadata_prefix.with_suffix(".stdout")
        metadata = link._json(native.read_regular(metadata_path, MAX_METADATA))
        package_ids(metadata, source, source_root)
        map_path = target_root / "geph-link.map"
        build_prefix = logs / (target + "-cargo")
        no_cargo_config(home, cargo_home)
        run([identities["cargo"]["path"], "rustc", *common, "--jobs", str(jobs), "--release", "--bin", "geph5-client",
             "--target", target, "--message-format=json", "--", "-C", "link-arg=-Wl,-map," + str(map_path)],
            cwd=home, env=env, prefix=build_prefix, timeout=timeout)
        actual = cargo_artifacts(build_prefix.with_suffix(".stdout"), metadata, source,
                                 source_root, target_root, target)
        linked_binary = map_binary(map_path, actual["binary"], target_root / target / "release")
        actual.update(link_map=map_path, cargo_metadata=metadata_path)
        destination = evidence / target / "linked"
        destination.mkdir()
        copied = {}
        for name, path in actual.items():
            copied[name] = destination / name
            copied[name].write_bytes(native.read_regular(path, link.MAX_BYTES))
        receipt = evidence / (target + "-linked.json")
        link.seal_linked_target(descriptor, native_receipt, evidence, source_hash,
            source["lock_sha256"], copied, str(linked_binary), str(actual["rlib"]), receipt)
        linked_receipts[target] = link._record(evidence, receipt)
        binaries.append(copied["binary"])
    final = evidence / "geph5-client"
    run([identities["lipo"]["path"], "-create", "-output", str(final), *map(str, binaries)],
        cwd=home, env=environment, prefix=logs / "lipo", timeout=min(timeout, 120))
    final.chmod(0o755)
    if source_inventory(source_root) != inventory:
        raise ValueError("materialized source changed during build")
    if input_records != [link._record(output, path) for path in sorted(snapshots.iterdir())]:
        raise ValueError("source input snapshot changed during build")
    if helper_hashes != {str(path): link.sha(native.read_regular(path, MAX_METADATA)) for path in helpers}:
        raise ValueError("producer/helper changed during build")
    if identities != {name: link._tool(Path(tools[name])) for name in identities}:
        raise ValueError("build tool changed during build")
    if (native.read_regular(libclang, link.MAX_BYTES) != libclang_bytes
            or native.read_regular(sdk / "SDKSettings.json", 1024 * 1024) != sdk_settings):
        raise ValueError("native toolchain changed during build")
    no_cargo_config(source_root, cargo_home)
    receipt_path = evidence / "native-release.json"
    write_json(receipt_path, {"schema_version": 1, "scope": "linked-macos-universal",
        "source_sha256": source_hash, "lock_sha256": source["lock_sha256"],
        "descriptor_sha256": native.descriptor_sha256(descriptor), "targets": source["targets"],
        "linked_receipts": linked_receipts, "final_binary": link._record(evidence, final)})
    result = link.verify_release_evidence(descriptor, receipt_path, evidence, source_hash, source["lock_sha256"])
    write_json(output / "producer.json", {"schema_version": 1, "scope": "offline-build-link-evidence",
        "helpers": helper_hashes, "tools": identities,
        "sdk_settings_sha256": link.sha(sdk_settings), "libclang_sha256": link.sha(libclang_bytes),
        "source_inventory": link._record(output, output / "source-files.json"),
        "inputs": input_records,
        "logs": [link._record(output, path) for path in sorted(logs.iterdir()) if path.stat().st_size],
        "release_receipt": link._record(output, receipt_path)})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "version", "lock", "crate", "native-archive", "output", "cargo-home",
                 "cargo", "rustc", "python", "clang", "ar", "lipo", "sdk", "libclang"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cmake", type=Path)
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    tools = {name: getattr(args, name) for name in ("cargo", "rustc", "python", "clang", "ar", "lipo", "sdk", "libclang")}
    if args.cmake:
        tools["cmake"] = args.cmake
    result = build_release(source_path=args.source, version_path=args.version, lock_path=args.lock,
        crate_path=args.crate, native_archive=args.native_archive, output=args.output,
        cargo_home=args.cargo_home, tools=tools, timeout=args.timeout, jobs=args.jobs)
    print(json.dumps({"scope": result["scope"], "receipt_sha256": result["receipt_sha256"],
                      "final_binary_sha256": result["final_binary_sha256"]}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run only reviewed Geph fixtures, with macOS network/private-file denial."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

import build_geph_native_release as producer
import geph_native_sqlite as native
import geph_native_sqlite_build as link
import geph_vendor_source as vendor

SESSION_TESTS = (
    "session::slipstream_isolation_tests::stream_open_errors_preserve_shared_session",
    "session::slipstream_isolation_tests::stalled_preferred_session_uses_reserve_without_harming_existing_stream",
    "session::slipstream_isolation_tests::failed_reserve_does_not_cancel_delayed_primary",
    "session::slipstream_isolation_tests::stalled_new_tunnel_preserves_existing_stream",
    "session::tests::direct_session_does_not_report_bridge",
    "session::tests::bridged_session_reports_bridge",
    "session::tests::missing_remote_addr_does_not_report_bridge",
    "session::tests::exit_log_label_uses_city_and_ip",
    "session::tests::exit_log_label_falls_back_to_ip_when_city_missing",
)
SQLITE_TESTS = (
    "database::slipstream_sqlite_tests::sqlite_cache_preserves_existing_schema_and_binary_values",
    "database::slipstream_sqlite_tests::sqlite_lazy_schema_waiter_observes_write",
)
SQLITE_CANCELLATION_TESTS = (
    "database::slipstream_sqlite_cancellation_tests::queued_cancel_releases_middle_waiter_and_preserves_cache",
    "database::slipstream_sqlite_cancellation_tests::running_cancel_hands_connection_to_next_writer_without_stale_lock",
    "database::slipstream_sqlite_cancellation_tests::cancelled_submitted_write_wakes_existing_cache_waiter",
    "database::slipstream_sqlite_cancellation_tests::cancelled_before_acquire_does_not_publish_or_strand_waiter",
    "database::slipstream_sqlite_cancellation_tests::cancelled_after_commit_before_caller_resume_wakes_waiter",
    "database::slipstream_sqlite_cancellation_tests::sql_error_wakes_only_for_committed_retry",
    "database::slipstream_sqlite_cancellation_tests::sql_rollback_wakes_only_for_committed_retry",
    "database::slipstream_sqlite_cancellation_tests::cancelled_remove_notifies_after_native_side_effect_commit",
)
ALLOWLIST = {"0.3.9": SESSION_TESTS,
             "0.4.3": SESSION_TESTS + SQLITE_TESTS + SQLITE_CANCELLATION_TESTS}
SANDBOX = Path("/usr/bin/sandbox-exec")
COMPILE_PROFILE = "(version 1)\n(allow default)\n(deny network*)\n"
NATIVE_TOOLS = {"cargo", "rustc", "clang", "ar", "sdk", "libclang"}


class QualificationError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_command(command: list[str], *, cwd: Path, env: dict[str, str],
                timeout: float, log: Path, log_limit: int = 1024 * 1024) -> dict:
    """Reap the launcher and kill its whole owned group, even on early exit."""
    started = time.monotonic()
    with log.open("w") as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        interrupted = None
        try:
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                code = 124
            except BaseException as error:
                interrupted = error
                code = 130
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    original_size = log.stat().st_size
    if original_size > log_limit:
        with log.open("rb") as stream:
            stream.seek(-log_limit, os.SEEK_END)
            tail = stream.read()
        log.write_bytes(b"[earlier command output truncated]\n" + tail)
    result = {"command": command, "returncode": code, "timed_out": timed_out,
              "elapsed_seconds": time.monotonic() - started, "log": str(log),
              "original_log_bytes": original_size, "retained_log_bytes": log.stat().st_size}
    log.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    if interrupted is not None:
        raise interrupted
    if code != 0:
        raise QualificationError(f"command failed ({code}); see {log}")
    return result


def reviewed_tests(source: Path, contract_path: Path, *, contract: dict | None = None) -> tuple[str, tuple[str, ...]]:
    contract = vendor.load_source_contract(contract_path) if contract is None else contract
    version = contract["crate"]["version"]
    if version not in ALLOWLIST:
        raise QualificationError(f"no reviewed synthetic test allowlist for {version}")
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if manifest.get("package", {}).get("version") != version or manifest.get(
            "package", {}).get("name") != "geph5-client":
        raise QualificationError("materialized crate identity differs from reviewed contract")
    if digest(source / "Cargo.lock") != contract["lock_sha256"]:
        raise QualificationError("materialized lock differs from reviewed contract")
    return version, ALLOWLIST[version]


def host_target() -> str:
    target = {"arm64": "aarch64-apple-darwin", "aarch64": "aarch64-apple-darwin",
              "x86_64": "x86_64-apple-darwin"}.get(platform.machine())
    if target is None:
        raise QualificationError("unsupported native synthetic host architecture")
    return target


def tool_identity(path: Path, *, executable: bool = True) -> dict:
    """Hash an explicitly selected physical tool without executing it."""
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise QualificationError("native tools must have absolute physical paths")
    fd = native._open_physical(path)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= link.MAX_BYTES
                or (executable and not os.access(path, os.X_OK))):
            raise QualificationError("native tool is not a bounded regular executable/file")
        digest, size = hashlib.sha256(), 0
        while block := os.read(fd, 1024 * 1024):
            size += len(block)
            if size > link.MAX_BYTES:
                raise QualificationError("native tool exceeds size limit")
            digest.update(block)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise QualificationError("native tool changed while reading")
        return {"path": str(path), "size": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def native_toolchain(tools: dict) -> dict:
    if set(tools) not in (NATIVE_TOOLS, NATIVE_TOOLS | {"cmake"}):
        raise QualificationError("native compilation requires all explicit tool paths")
    identities = {name: tool_identity(path) for name, path in tools.items()
                  if name not in ("sdk", "libclang")}
    sdk = Path(tools["sdk"])
    if not sdk.is_absolute():
        raise QualificationError("native SDK must have an absolute physical path")
    sdk = link._root(sdk)
    identities["sdk"] = {"path": str(sdk), "settings_sha256": link.sha(
        native.read_regular(sdk / "SDKSettings.json", 1024 * 1024))}
    if Path(tools["libclang"]).name != "libclang.dylib":
        raise QualificationError("explicit libclang.dylib is required")
    identities["libclang"] = tool_identity(tools["libclang"], executable=False)
    return identities


def prepare_native(source: Path, contract: dict, source_sha256: str, *, receipt: Path,
                   artifacts: Path, cargo_home: Path, tools: dict, jobs: int) -> dict:
    if type(jobs) is not int or jobs != 1:
        raise QualificationError("native synthetic build jobs must be explicitly set to 1")
    source, artifacts, cargo_home = map(link._root, (source, artifacts, cargo_home))
    descriptor = contract["native_sqlite"]
    lock = native.read_regular(source / "Cargo.lock", producer.MAX_METADATA)
    native.verify_wrapper_lock(descriptor, lock, contract["lock_sha256"])
    native.verify_materialized(descriptor, source)
    identities = native_toolchain(tools)
    proof = link.verify_native_build(descriptor, receipt, artifacts, source_sha256, contract["lock_sha256"])
    target = host_target()
    if proof["target"] != target:
        raise QualificationError("native archive receipt does not match the host target")
    if proof["tools"] != {name: identities[name] for name in ("clang", "ar", "sdk")}:
        raise QualificationError("explicit clang/ar/SDK identities differ from native proof")
    producer.no_cargo_config(source, cargo_home)
    return {"source": source, "contract": contract, "source_sha256": source_sha256,
            "receipt": Path(receipt).absolute(), "artifacts": artifacts, "cargo_home": cargo_home,
            "tools": tools, "identities": identities, "proof": proof, "target": target,
            "inventory": producer.source_inventory(source)}


def recheck_native(context: dict) -> None:
    source, contract = context["source"], context["contract"]
    if producer.source_inventory(source) != context["inventory"]:
        raise QualificationError("materialized source changed during native qualification")
    if native_toolchain(context["tools"]) != context["identities"]:
        raise QualificationError("explicit native toolchain changed during qualification")
    proof = link.verify_native_build(contract["native_sqlite"], context["receipt"], context["artifacts"],
                                     context["source_sha256"], contract["lock_sha256"])
    if proof["receipt_sha256"] != context["proof"]["receipt_sha256"]:
        raise QualificationError("native archive receipt changed during qualification")
    producer.no_cargo_config(source, context["cargo_home"])


COMPILE_PROBE = r'''
import errno, json, socket, subprocess, sys
def network_errno():
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=1).close()
    except OSError as error:
        return error.errno
    return "UNEXPECTED_SUCCESS"
child = subprocess.run([sys.executable, "-I", "-S", "-c",
    "import errno,socket\ntry:\n socket.create_connection(('127.0.0.1',9),timeout=1).close()\n"
    "except OSError as e:\n print(e.errno)\nelse:\n print('UNEXPECTED_SUCCESS')"],
    capture_output=True, text=True, timeout=5, check=True)
result = {"network": network_errno(), "child_network": child.stdout.strip()}
print(json.dumps(result))
assert result == {"network": errno.EPERM, "child_network": str(errno.EPERM)}, result
'''


def compile_sandbox_selftest(base: list[str], *, cwd: Path, env: dict, evidence: Path) -> None:
    log = evidence / "compile-sandbox-probe.log"
    run_command(base + [str(Path(sys.executable).resolve()), "-I", "-S", "-c", COMPILE_PROBE],
                cwd=cwd, env=env, timeout=15, log=log)
    result = json.loads(native.read_regular(log, 16 * 1024))
    if result != {"network": 1, "child_network": "1"}:
        raise QualificationError("compile sandbox and child must deny network with EPERM")


def native_compile(context: dict, *, target: Path, root: Path, evidence: Path,
                   timeout: float) -> Path:
    home, temporary = root / "compile-home", root / "compile-tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    contract, identities = context["contract"], context["identities"]
    env = link.cargo_environment(contract["native_sqlite"], context["receipt"], context["artifacts"],
        context["source_sha256"], contract["lock_sha256"], inherited={
            "PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temporary),
            "LC_ALL": "C", "ZERO_AR_DATE": "1"})
    files = context["proof"]["files"]
    expected_native = {
        "SQLITE3_INCLUDE_DIR": str((context["artifacts"] / files["include/sqlite3.h"]["path"]).parent),
        "SQLITE3_LIB_DIR": str((context["artifacts"] / files["libsqlite3.a"]["path"]).parent),
        "SQLITE3_STATIC": "1", "SQLITE3_NO_PKG_CONFIG": "1"}
    if any(env.get(key) != value for key, value in expected_native.items()):
        raise QualificationError("native Cargo environment differs from the verified host proof")
    # The caller's independently validated paths select executables, never receipt paths.
    env.update(CARGO_HOME=str(context["cargo_home"]), CARGO_NET_OFFLINE="true",
               CARGO_TARGET_DIR=str(target), RUSTC=identities["rustc"]["path"],
               CC=identities["clang"]["path"], AR=identities["ar"]["path"],
               SDKROOT=identities["sdk"]["path"], LIBCLANG_PATH=str(Path(identities["libclang"]["path"]).parent))
    env["CARGO_TARGET_" + context["target"].upper().replace("-", "_") + "_LINKER"] = identities["clang"]["path"]
    if "cmake" in identities:
        env["CMAKE"] = identities["cmake"]["path"]
    recheck_native(context)
    producer.no_cargo_config(home, context["cargo_home"])
    profile = evidence / "compile.sb"
    profile.write_text(COMPILE_PROFILE)
    base = [str(SANDBOX), "-p", COMPILE_PROFILE]
    compile_sandbox_selftest(base, cwd=home, env=env, evidence=evidence)
    producer.no_cargo_config(home, context["cargo_home"])
    common = ["--manifest-path", str(context["source"] / "Cargo.toml"), "--locked", "--offline",
              "--features", ",".join(contract["features"])]
    metadata_prefix = evidence / "native-metadata"
    producer.run(base + [identities["cargo"]["path"], "metadata", *common,
                        "--filter-platform", context["target"], "--format-version", "1"],
                 cwd=home, env=env, timeout=timeout, prefix=metadata_prefix, stdout_limit=producer.MAX_METADATA)
    metadata = link._json(native.read_regular(metadata_prefix.with_suffix(".stdout"), producer.MAX_METADATA))
    producer.package_ids(metadata, contract, context["source"])
    recheck_native(context)
    producer.no_cargo_config(home, context["cargo_home"])
    # Bind the same fixed policy again before launching a compiler child.
    if native.read_regular(profile, 1024) != COMPILE_PROFILE.encode():
        raise QualificationError("compile sandbox profile changed before compilation")
    prefix = evidence / "native-compile"
    producer.run(base + [identities["cargo"]["path"], "test", *common, "--lib", "--no-run",
                        "--target", context["target"], "--jobs", "1", "--message-format=json",
                        "--target-dir", str(target)], cwd=home, env=env, timeout=timeout,
                 prefix=prefix, stdout_limit=8 * 1024 * 1024)
    recheck_native(context)
    producer.no_cargo_config(home, context["cargo_home"])
    return prefix.with_suffix(".stdout")


def compiled_binary(log: Path, source: Path, target: Path) -> Path:
    candidates = set()
    for line in log.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") != "compiler-artifact" or not row.get("profile", {}).get("test"):
            continue
        item = row.get("target", {})
        if item.get("name") != "geph5_client" or Path(item.get("src_path", "")).resolve() != (
                source / "src/lib.rs").resolve() or not row.get("executable"):
            continue
        executable = Path(row["executable"]).resolve()
        if not executable.is_relative_to(target.resolve()) or not executable.is_file():
            raise QualificationError("compiled test executable is outside the owned target")
        candidates.add(executable)
    if len(candidates) != 1:
        raise QualificationError("expected exactly one compiled Geph libtest executable")
    return candidates.pop()


def runtime_environment(scratch: Path) -> dict[str, str]:
    # HOME is preserved; the OS sandbox denies actual home data. Never inherit
    # credentials, dynamic-loader overrides, Rust test filters or shell hooks.
    env = {name: os.environ[name] for name in ("HOME", "PATH", "LANG", "LC_ALL", "TZ")
           if name in os.environ}
    for name, directory in (("TMPDIR", "tmp"), ("XDG_CACHE_HOME", "cache"),
                            ("XDG_CONFIG_HOME", "config")):
        path = scratch / directory
        path.mkdir()
        env[name] = str(path)
    return env


def sandbox_profile(target: Path, scratch: Path, sentinel: Path) -> str:
    homes = {Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(), Path.home().resolve()}
    interpreter = Path(sys.executable).resolve()
    prefix = Path(sys.base_prefix).resolve()
    if prefix == Path("/") or prefix in homes:
        raise QualificationError("interpreter prefix is too broad for private-file isolation")
    quote = lambda p: json.dumps(str(p.resolve()))
    denied = homes | {Path("/Library/Application Support/Slipstream"),
                      Path("/Library/Keychains")}
    return "\n".join([
        "(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)",
        "(deny file-read* " + " ".join(f"(subpath {quote(p)})" for p in sorted(denied)) + ")",
        "(allow file-read* " + " ".join(f"(subpath {quote(p)})" for p in (target, scratch, prefix))
        + f" (literal {quote(interpreter)}))",
        f"(deny file-read* (literal {quote(sentinel)}))",
        f"(allow file-write* (subpath {quote(scratch)}) (literal \"/dev/null\"))",
    ]) + "\n"


PROBE = r'''
import errno, json, pathlib, socket, sys
results = {}
for name, action in (
    ("private_read", lambda: pathlib.Path(sys.argv[1]).read_bytes()),
    ("unowned_write", lambda: pathlib.Path(sys.argv[2]).write_text("unexpected")),
    ("network", lambda: socket.create_connection(("127.0.0.1", 9), timeout=1)),
):
    try:
        action()
        results[name] = "UNEXPECTED_SUCCESS"
    except OSError as error:
        results[name] = error.errno
pathlib.Path(sys.argv[3]).write_text("owned fixture write")
print(json.dumps(results))
assert all(value == errno.EPERM for value in results.values()), results
'''


def sandbox_selftest(base: list[str], *, scratch: Path, sentinel: Path,
                     env: dict[str, str], evidence: Path) -> None:
    log = evidence / "sandbox-probe.log"
    run_command(base + [sys.executable, "-I", "-S", "-c", PROBE, str(sentinel),
                       str(sentinel.with_name("forbidden-write")), str(scratch / "probe-write")],
                cwd=scratch, env=env, timeout=15, log=log)
    try:
        result = json.loads(log.read_text())
    except ValueError as error:
        raise QualificationError("sandbox probe returned invalid evidence") from error
    if result != {"private_read": 1, "unowned_write": 1, "network": 1}:
        raise QualificationError("sandbox denial probes did not all return EPERM")


def require_tests(log: Path, expected: tuple[str, ...]) -> None:
    discovered = re.findall(r"(?m)^(\S+): test$", log.read_text())
    if any(discovered.count(name) != 1 for name in expected):
        raise QualificationError("compiled libtest is missing or duplicates a reviewed test")


def require_single_pass(log: Path, name: str) -> None:
    text = log.read_text()
    if (re.findall(r"(?m)^running (\d+) tests?$", text) != ["1"]
            or len(re.findall(r"(?m)^test " + re.escape(name) + r" \.\.\. ok$", text)) != 1
            or len(re.findall(r"(?m)^test result:", text)) != 1
            or not re.search(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;", text)):
        raise QualificationError(f"missing positive exact-case result for {name}")


def qualify(source: Path, contract: Path, evidence: Path, *, compile_timeout: float = 1200,
            case_timeout: float = 60, native_receipt: Path | None = None,
            native_artifacts_root: Path | None = None, cargo_home: Path | None = None,
            native_tools: dict | None = None, build_jobs: int | None = None) -> dict:
    if sys.platform != "darwin" or not SANDBOX.is_file():
        raise QualificationError("macOS sandbox-exec is required; no unsandboxed fallback")
    if not all(math.isfinite(t) and t > 0 for t in (compile_timeout, case_timeout)):
        raise QualificationError("timeouts must be positive")
    source_bytes = native.read_regular(Path(contract), vendor.MAX_SOURCE_BYTES)
    source_contract = vendor._json_object(source_bytes, "Geph source contract")
    vendor._validate_source_contract(source_contract)
    source_sha256 = link.sha(source_bytes)
    supplied = (native_receipt, native_artifacts_root, cargo_home, native_tools, build_jobs)
    context = None
    if "native_sqlite" in source_contract:
        if any(value is None for value in supplied):
            raise QualificationError("native SOURCE requires explicit receipt, artifact root, Cargo home, tools and build jobs")
        source, contract, evidence = map(lambda p: Path(p).absolute(), (source, contract, evidence))
        link._root(evidence.parent)
        context = prepare_native(source, source_contract, source_sha256,
            receipt=native_receipt, artifacts=native_artifacts_root, cargo_home=cargo_home,
            tools=native_tools, jobs=build_jobs)
    else:
        if any(value is not None for value in supplied):
            raise QualificationError("native compile arguments require native SOURCE")
        source, contract, evidence = source.resolve(), contract.resolve(), evidence.resolve()
    version, tests = reviewed_tests(source, contract, contract=source_contract)
    evidence.mkdir(parents=True, exist_ok=False)
    summary = {"status": "failed", "version": version, "expected_tests": list(tests),
               "passed_tests": [], "inputs": {str(contract): source_sha256, **{str(p): digest(p) for p in (
                   source / "Cargo.toml", source / "Cargo.lock",
                   source / "src/lib.rs", source / "src/session.rs", source / "src/database.rs")}}}
    if context is not None:
        producer.write_json(evidence / "source-files.json", context["inventory"])
        summary["native_compile"] = {"target": context["target"],
            "receipt_sha256": context["proof"]["receipt_sha256"], "tools": context["identities"],
            "source_inventory_sha256": digest(evidence / "source-files.json"),
            "compile_profile_sha256": link.sha(COMPILE_PROFILE.encode()), "build_jobs": 1}
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        with tempfile.TemporaryDirectory(prefix="geph-synthetic-") as temporary:
            root = Path(temporary).resolve()
            target, scratch, sentinel = root / "target", root / "runtime", root / "private-sentinel"
            target.mkdir()
            scratch.mkdir()
            sentinel.write_text("synthetic private-file probe; no account data")
            env = runtime_environment(scratch)
            profile = root / "runtime.sb"
            profile.write_text(sandbox_profile(target, scratch, sentinel))
            (evidence / "runtime.sb").write_text(profile.read_text())
            base = [str(SANDBOX), "-f", str(profile)]
            sandbox_selftest(base, scratch=scratch, sentinel=sentinel, env=env, evidence=evidence)
            if context is None:
                compile_log = evidence / "compile.log"
                # Preserve the legacy compile contract. The native path below
                # additionally bounds the build-script environment and network.
                run_command(["cargo", "test", "--manifest-path", str(source / "Cargo.toml"),
                             "--locked", "--features", "aws_lambda", "--lib", "--no-run",
                             "--message-format=json", "--target-dir", str(target)],
                            cwd=source, env=dict(os.environ), timeout=compile_timeout, log=compile_log,
                            log_limit=8 * 1024 * 1024)
            else:
                compile_log = native_compile(context, target=target, root=root,
                                             evidence=evidence, timeout=compile_timeout)
            executable = compiled_binary(compile_log, source, target)
            summary["binary_sha256"] = digest(executable)
            listing = evidence / "list.log"
            run_command(base + [str(executable), "--list"], cwd=scratch, env=env,
                        timeout=case_timeout, log=listing)
            require_tests(listing, tests)
            for index, name in enumerate(tests):
                log = evidence / f"case-{index + 1:02d}.log"
                run_command(base + [str(executable), name, "--exact", "--test-threads=1", "--nocapture"],
                            cwd=scratch, env=env, timeout=case_timeout, log=log)
                require_single_pass(log, name)
                summary["passed_tests"].append(name)
            summary["status"] = "passed"
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-contract", type=Path, default=Path("vendor/geph/SOURCE.json"))
    parser.add_argument("--evidence-dir", required=True, type=Path)
    for flag in ("native-receipt", "native-artifacts-root", "cargo-home", *sorted(NATIVE_TOOLS), "cmake"):
        parser.add_argument("--" + flag, type=Path)
    parser.add_argument("--build-jobs", type=int)
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise QualificationError(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        selected = {name: getattr(args, name) for name in NATIVE_TOOLS | {"cmake"}
                    if getattr(args, name) is not None}
        result = qualify(args.source_root, args.source_contract, args.evidence_dir,
                         native_receipt=args.native_receipt, native_artifacts_root=args.native_artifacts_root,
                         cargo_home=args.cargo_home, native_tools=selected or None, build_jobs=args.build_jobs)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Geph synthetic qualification failed: {error}", file=sys.stderr)
        return 1
    print(f"Geph {result['version']}: {len(result['passed_tests'])} exact synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

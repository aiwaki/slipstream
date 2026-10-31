#!/usr/bin/env python3
"""Run only reviewed Geph fixtures, with macOS network/private-file denial."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

from geph_vendor_source import load_source_contract
import geph_rsa_fixture

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


def reviewed_tests(source: Path, contract_path: Path) -> tuple[str, tuple[str, ...]]:
    contract = load_source_contract(contract_path)
    version = contract["crate"]["version"]
    if version not in ALLOWLIST:
        raise QualificationError(f"no reviewed synthetic test allowlist for {version}")
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if manifest.get("package", {}).get("version") != version or manifest.get(
            "package", {}).get("name") != "geph5-client":
        raise QualificationError("materialized crate identity differs from reviewed contract")
    if digest(source / "Cargo.lock") != contract["lock_sha256"]:
        raise QualificationError("materialized lock differs from reviewed contract")
    tests = ALLOWLIST[version]
    if "embedded_packages" in contract:
        if version != "0.4.3" or "native_sqlite" in contract:
            raise QualificationError("no reviewed RSA fixture for this source-owned client")
        tests += geph_rsa_fixture.RSA_TESTS
    return version, tests


def compiled_binary(log: Path, source: Path, target: Path, *,
                    target_name: str = "geph5_client", target_source: str = "src/lib.rs",
                    is_test: bool = True) -> Path:
    candidates = set()
    for line in log.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") != "compiler-artifact" or row.get("profile", {}).get("test") is not is_test:
            continue
        item = row.get("target", {})
        if item.get("name") != target_name or Path(item.get("src_path", "")).resolve() != (
                source / target_source).resolve() or not row.get("executable"):
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


def sandbox_profile(target: Path, scratch: Path, sentinel: Path, *,
                    python_probe: bool = False) -> str:
    homes = {Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(), Path.home().resolve()}
    quote = lambda p: json.dumps(str(p.resolve()))
    readable = [target, scratch]
    interpreter_rule = ""
    if python_probe:
        # Only the trusted -I/-S Python probe needs its runtime. Native Geph
        # fixtures must not inherit this exception, including a hosted prefix
        # beneath HOME.
        interpreter = Path(sys.executable).resolve()
        prefix = Path(sys.base_prefix).resolve()
        if prefix == Path("/") or prefix in homes:
            raise QualificationError("interpreter prefix is too broad for private-file isolation")
        readable.append(prefix)
        interpreter_rule = f" (literal {quote(interpreter)})"
    denied = homes | {Path("/Library/Application Support/Slipstream"),
                      Path("/Library/Keychains")}
    return "\n".join([
        "(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)",
        "(deny file-read* " + " ".join(f"(subpath {quote(p)})" for p in sorted(denied)) + ")",
        "(allow file-read* " + " ".join(f"(subpath {quote(p)})" for p in readable)
        + interpreter_rule + ")",
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
            case_timeout: float = 60) -> dict:
    if sys.platform != "darwin" or not SANDBOX.is_file():
        raise QualificationError("macOS sandbox-exec is required; no unsandboxed fallback")
    if compile_timeout <= 0 or case_timeout <= 0:
        raise QualificationError("timeouts must be positive")
    source, contract, evidence = source.resolve(), contract.resolve(), evidence.resolve()
    version, tests = reviewed_tests(source, contract)
    evidence.mkdir(parents=True, exist_ok=False)
    summary = {"status": "failed", "version": version, "expected_tests": list(tests),
               "passed_tests": [], "inputs": {str(p): digest(p) for p in (
                   contract, source / "Cargo.toml", source / "Cargo.lock",
                   source / "src/lib.rs", source / "src/session.rs", source / "src/database.rs")}}
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    production_snapshot = None
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
            probe_profile = root / "probe.sb"
            probe_profile.write_text(sandbox_profile(target, scratch, sentinel, python_probe=True))
            (evidence / "probe.sb").write_text(probe_profile.read_text())
            sandbox_selftest([str(SANDBOX), "-f", str(probe_profile)], scratch=scratch,
                             sentinel=sentinel, env=env, evidence=evidence)
            build_source = source
            compile_deadline = time.monotonic() + compile_timeout
            def remaining_compile_time():
                remaining = compile_deadline - time.monotonic()
                if remaining <= 0:
                    raise QualificationError("shared compile deadline exhausted")
                return remaining
            if any(name.startswith("rsa_composition_tests::") for name in tests):
                fixture = geph_rsa_fixture.prepare(source, contract, scratch / "rsa")
                production_snapshot = fixture["production_files"]
                build_source = fixture["source"]
                summary["rsa_fixture"] = {
                    "catalog_sha256": fixture["catalog_sha256"],
                    "production_files": production_snapshot,
                    "test_copy_files": fixture["test_files"],
                    "fixture_files": fixture["fixture_files"],
                    "oracle_scope": "separate synthetic executable; never linked or shipped",
                    "production_unchanged": False,
                }
                oracle_log = evidence / "oracle-compile.log"
                oracle_target = target / "oracle"
                run_command(["cargo", "build", "--manifest-path", str(fixture["oracle"] / "Cargo.toml"),
                             "--locked", "--bin", "sign_adapter", "--message-format=json",
                             "--target-dir", str(oracle_target)], cwd=fixture["oracle"],
                            env=dict(os.environ), timeout=remaining_compile_time(), log=oracle_log,
                            log_limit=8 * 1024 * 1024)
                oracle = compiled_binary(oracle_log, fixture["oracle"], oracle_target,
                                         target_name="sign_adapter", target_source="src/bin/sign_adapter.rs",
                                         is_test=False)
                copied_oracle = fixture["root"] / "legacy-target/debug/sign_adapter"
                copied_oracle.parent.mkdir(parents=True)
                shutil.copy2(oracle, copied_oracle)
                if digest(copied_oracle) != digest(oracle):
                    raise QualificationError("synthetic oracle changed while copying")
                summary["rsa_fixture"]["oracle_binary_sha256"] = digest(copied_oracle)
            compile_log = evidence / "compile.log"
            # Build scripts/dependency fetching remain part of the existing build
            # phase. No Geph libtest code executes during this no-run command.
            run_command(["cargo", "test", "--manifest-path", str(build_source / "Cargo.toml"),
                         "--locked", "--features", "aws_lambda", "--lib", "--no-run",
                         "--message-format=json", "--target-dir", str(target)],
                        cwd=build_source, env=dict(os.environ), timeout=remaining_compile_time(), log=compile_log,
                        log_limit=8 * 1024 * 1024)
            executable = compiled_binary(compile_log, build_source, target)
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
            if production_snapshot is not None:
                geph_rsa_fixture.assert_unchanged(build_source, fixture["test_files"])
                geph_rsa_fixture.assert_unchanged(fixture["oracle"], {
                    name.removeprefix("legacy-oracle/"): value
                    for name, value in fixture["fixture_files"].items()
                    if name.startswith("legacy-oracle/")})
                geph_rsa_fixture.assert_unchanged(source, production_snapshot)
                summary["rsa_fixture"]["production_unchanged"] = True
            summary["status"] = "passed"
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        if production_snapshot is not None:
            try:
                geph_rsa_fixture.assert_unchanged(source, production_snapshot)
            except (OSError, ValueError) as error:
                summary["status"] = "failed"
                summary["error"] = str(error)
                (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
                raise QualificationError(str(error)) from error
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-contract", type=Path, default=Path("vendor/geph/SOURCE.json"))
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise QualificationError(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        result = qualify(args.source_root, args.source_contract, args.evidence_dir)
    except (OSError, ValueError, QualificationError) as error:
        print(f"Geph synthetic qualification failed: {error}", file=sys.stderr)
        return 1
    print(f"Geph {result['version']}: {len(result['passed_tests'])} exact synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

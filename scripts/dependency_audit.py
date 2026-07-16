#!/usr/bin/env python3
"""Scan and validate Slipstream's exact release SBOM against a review policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path


SCHEMA_VERSION = 1
GENERATOR = "slipstream-dependency-audit-1"
REPORT_NAME = "dependency-audit.json"
DEFAULT_POLICY = (
    Path(__file__).resolve().parents[1] / "security/dependency-audit-policy.json"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
MAX_SCANNER_BYTES = 128 * 1024 * 1024
VENDORED_TRANSITIVE_COVERAGE = ("top-level-only", "full")


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_object(path: Path, label: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be a JSON object")
    return data


def load_policy(path: Path) -> dict:
    policy = _read_json_object(path, "dependency audit policy")
    if policy.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported dependency audit policy schema")
    rules = policy.get("rules")
    if rules != {"informational": "record", "unreviewed": "block"}:
        raise ValueError("dependency audit policy rules are not fail-closed")
    scanner = policy.get("scanner")
    if not isinstance(scanner, dict):
        raise ValueError("dependency audit scanner policy is required")
    if scanner.get("repository") != "google/osv-scanner":
        raise ValueError("dependency audit scanner repository is not trusted")
    version = scanner.get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", version
    ):
        raise ValueError("dependency audit scanner version is invalid")
    assets = scanner.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError("dependency audit scanner assets are required")
    for platform, asset in assets.items():
        if not isinstance(platform, str) or not isinstance(asset, dict):
            raise ValueError("dependency audit scanner asset is invalid")
        if not isinstance(asset.get("name"), str) or not SHA256_PATTERN.fullmatch(
            str(asset.get("sha256", ""))
        ):
            raise ValueError(f"dependency audit scanner asset {platform} is invalid")

    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValueError("dependency audit exceptions must be a list")
    exception_ids: set[str] = set()
    exception_keys: set[tuple[str, str, str, str]] = set()
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise ValueError("dependency audit exception is invalid")
        required_strings = (
            "id",
            "ecosystem",
            "package",
            "version",
            "expires",
            "reason",
        )
        if not all(
            isinstance(exception.get(key), str) and exception[key]
            for key in required_strings
        ):
            raise ValueError("dependency audit exception is incomplete")
        if exception["id"] in exception_ids:
            raise ValueError(f"duplicate dependency audit exception {exception['id']}")
        exception_ids.add(exception["id"])
        try:
            date.fromisoformat(exception["expires"])
        except ValueError as exc:
            raise ValueError(f"invalid expiry for exception {exception['id']}") from exc
        advisories = exception.get("advisories")
        if not isinstance(advisories, list) or not advisories or not all(
            isinstance(value, str) and value for value in advisories
        ):
            raise ValueError(f"invalid advisories for exception {exception['id']}")
        for advisory_id in advisories:
            key = (
                exception["ecosystem"],
                exception["package"],
                exception["version"],
                advisory_id,
            )
            if key in exception_keys:
                raise ValueError(
                    "dependency audit exceptions overlap for "
                    f"{exception['package']} {exception['version']} {advisory_id}"
                )
            exception_keys.add(key)
    return policy


def scanner_asset(policy: dict, platform: str) -> dict:
    asset = policy["scanner"]["assets"].get(platform)
    if not isinstance(asset, dict):
        raise ValueError(f"unsupported dependency scanner platform: {platform}")
    return asset


def _tls_context() -> ssl.SSLContext:
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def expected_scanner_metadata(policy: dict, platform: str) -> dict:
    asset = scanner_asset(policy, platform)
    return {
        "asset": asset["name"],
        "name": "osv-scanner",
        "platform": platform,
        "sha256": asset["sha256"],
        "version": policy["scanner"]["version"],
    }


def fetch_scanner(*, policy_path: Path, platform: str, output: Path) -> dict:
    policy = load_policy(policy_path)
    scanner = policy["scanner"]
    asset = scanner_asset(policy, platform)
    url = (
        f"https://github.com/{scanner['repository']}/releases/download/"
        f"v{scanner['version']}/{asset['name']}"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": GENERATOR})
        with urllib.request.urlopen(
            request, timeout=60, context=_tls_context()
        ) as response, temporary.open("wb") as handle:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SCANNER_BYTES:
                raise ValueError("dependency scanner asset exceeds the size limit")
            received = 0
            while block := response.read(1024 * 1024):
                received += len(block)
                if received > MAX_SCANNER_BYTES:
                    raise ValueError("dependency scanner asset exceeds the size limit")
                handle.write(block)
        actual_sha256 = hash_file(temporary)
        if actual_sha256 != asset["sha256"]:
            raise ValueError(
                "downloaded dependency scanner checksum does not match policy"
            )
        temporary.chmod(0o755)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "name": asset["name"],
        "platform": platform,
        "sha256": asset["sha256"],
        "url": url,
        "version": scanner["version"],
    }


def verify_scanner(*, scanner_path: Path, policy: dict, platform: str) -> dict:
    asset = scanner_asset(policy, platform)
    metadata = scanner_path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(scanner_path, os.X_OK):
        raise ValueError("dependency scanner must be an executable regular file")
    actual_sha256 = hash_file(scanner_path)
    if actual_sha256 != asset["sha256"]:
        raise ValueError("dependency scanner checksum does not match policy")
    completed = subprocess.run(
        (str(scanner_path), "--version"),
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=15,
    )
    version_output = f"{completed.stdout}\n{completed.stderr}"
    expected_version = policy["scanner"]["version"]
    if completed.returncode != 0 or not re.search(
        rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])", version_output
    ):
        raise ValueError("dependency scanner version does not match policy")
    return expected_scanner_metadata(policy, platform)


def run_osv_scan(*, scanner_path: Path, sbom_path: Path) -> dict:
    descriptor, output_name = tempfile.mkstemp(prefix="slipstream-osv-", suffix=".json")
    os.close(descriptor)
    output = Path(output_name)
    try:
        completed = subprocess.run(
            (
                str(scanner_path),
                "scan",
                "source",
                "--format",
                "json",
                "--all-packages",
                "-L",
                str(sbom_path),
                "--output-file",
                str(output),
            ),
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=300,
        )
        if completed.returncode not in {0, 1}:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            message = (
                f"dependency scanner failed with exit code "
                f"{completed.returncode}{suffix}"
            )
            raise RuntimeError(message)
        return _read_json_object(output, "OSV scanner result")
    finally:
        output.unlink(missing_ok=True)


def _informational_kind(vulnerability: dict) -> str | None:
    kinds: set[str] = set()
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("informational"):
        kinds.add(str(database_specific["informational"]))
    affected = vulnerability.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            details = entry.get("database_specific")
            if isinstance(details, dict) and details.get("informational"):
                kinds.add(str(details["informational"]))
    return ",".join(sorted(kinds)) or None


def _advisory_ids(vulnerability: dict) -> tuple[str, ...]:
    values = [vulnerability.get("id")]
    aliases = vulnerability.get("aliases")
    if isinstance(aliases, list):
        values.extend(aliases)
    ids = sorted({value for value in values if isinstance(value, str) and value})
    if not ids:
        raise ValueError("OSV vulnerability is missing an identifier")
    return tuple(ids)


def _matching_exception(
    *, policy: dict, package: dict, advisory_ids: tuple[str, ...]
) -> dict | None:
    matches = []
    advisory_set = set(advisory_ids)
    for exception in policy["exceptions"]:
        if (
            exception["ecosystem"] == package.get("ecosystem")
            and exception["package"] == package.get("name")
            and exception["version"] == package.get("version")
            and advisory_set.intersection(exception["advisories"])
        ):
            matches.append(exception)
    if len(matches) > 1:
        raise ValueError(
            f"multiple dependency audit exceptions match {advisory_ids[0]}"
        )
    return matches[0] if matches else None


def evaluate_osv_result(
    *,
    result: dict,
    policy: dict,
    evaluated_on: date,
) -> tuple[list[dict], int]:
    results = result.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV scanner result is missing results")
    findings: list[dict] = []
    packages_seen: set[tuple[str, str, str]] = set()
    findings_seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for source in results:
        if not isinstance(source, dict) or not isinstance(source.get("packages"), list):
            raise ValueError("OSV scanner result contains an invalid package source")
        for entry in source["packages"]:
            if not isinstance(entry, dict) or not isinstance(
                entry.get("package"), dict
            ):
                raise ValueError("OSV scanner result contains an invalid package")
            package = entry["package"]
            coordinates = tuple(
                package.get(key) for key in ("ecosystem", "name", "version")
            )
            if not all(isinstance(value, str) and value for value in coordinates):
                raise ValueError("OSV scanner package coordinates are incomplete")
            packages_seen.add(coordinates)
            vulnerabilities = entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ValueError("OSV scanner vulnerabilities must be a list")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("OSV scanner vulnerability is invalid")
                advisory_ids = _advisory_ids(vulnerability)
                finding_key = (*coordinates, advisory_ids)
                if finding_key in findings_seen:
                    continue
                findings_seen.add(finding_key)
                finding = {
                    "aliases": list(advisory_ids[1:]),
                    "id": advisory_ids[0],
                    "package": {
                        "ecosystem": coordinates[0],
                        "name": coordinates[1],
                        "version": coordinates[2],
                    },
                }
                if vulnerability.get("withdrawn"):
                    finding["classification"] = "withdrawn"
                elif informational := _informational_kind(vulnerability):
                    finding["classification"] = "informational"
                    finding["informational"] = informational
                else:
                    exception = _matching_exception(
                        policy=policy,
                        package=package,
                        advisory_ids=advisory_ids,
                    )
                    if exception is None:
                        finding["classification"] = "blocking"
                    else:
                        expiry = date.fromisoformat(exception["expires"])
                        finding["exception"] = {
                            "expires": exception["expires"],
                            "id": exception["id"],
                        }
                        finding["classification"] = (
                            "accepted_exception"
                            if evaluated_on <= expiry
                            else "blocking"
                        )
                        if evaluated_on > expiry:
                            finding["reason"] = "expired_exception"
                findings.append(finding)
    findings.sort(
        key=lambda item: (
            item["package"]["ecosystem"],
            item["package"]["name"].lower(),
            item["package"]["version"],
            item["id"],
        )
    )
    return findings, len(packages_seen)


def build_audit_report(
    *,
    osv_result: dict,
    policy: dict,
    policy_path: Path,
    sbom_path: Path,
    scanner: dict,
    source_commit: str,
    target: str,
    evaluated_on: date,
    vendored_transitive_dependencies: str = "top-level-only",
) -> dict:
    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if not target:
        raise ValueError("release target is required")
    if vendored_transitive_dependencies not in VENDORED_TRANSITIVE_COVERAGE:
        raise ValueError("vendored transitive dependency coverage is invalid")
    findings, packages_scanned = evaluate_osv_result(
        result=osv_result,
        policy=policy,
        evaluated_on=evaluated_on,
    )
    sbom_package_count = _sbom_package_count(sbom_path)
    if packages_scanned != sbom_package_count:
        raise ValueError(
            "dependency scanner package count does not match the release SBOM"
        )
    counts = {
        classification: sum(
            finding["classification"] == classification for finding in findings
        )
        for classification in (
            "accepted_exception",
            "blocking",
            "informational",
            "withdrawn",
        )
    }
    return {
        "coverage": {
            "sbom_packages": "all",
            "vendored_transitive_dependencies": vendored_transitive_dependencies,
        },
        "evaluated_on": evaluated_on.isoformat(),
        "findings": findings,
        "generator": GENERATOR,
        "inputs": {
            "policy_sha256": hash_file(policy_path),
            "sbom_sha256": hash_file(sbom_path),
        },
        "scanner": scanner,
        "schema_version": SCHEMA_VERSION,
        "source": {"commit": source_commit, "target": target},
        "status": "fail" if counts["blocking"] else "pass",
        "summary": {
            **counts,
            "advisories": len(findings),
            "packages_scanned": packages_scanned,
        },
    }


def write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sbom_package_count(path: Path) -> int:
    sbom = _read_json_object(path, "release SBOM")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("release SBOM does not contain packages")
    return len(packages)


def validate_audit_report(
    report: object,
    *,
    policy_path: Path,
    sbom_path: Path,
    source_commit: str,
    target: str,
    vendored_transitive_dependencies: str = "top-level-only",
) -> dict:
    if not isinstance(report, dict):
        raise ValueError("dependency audit report must be a JSON object")
    if vendored_transitive_dependencies not in VENDORED_TRANSITIVE_COVERAGE:
        raise ValueError("vendored transitive dependency coverage is invalid")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "status": "pass",
        "source": {"commit": source_commit, "target": target},
        "coverage": {
            "sbom_packages": "all",
            "vendored_transitive_dependencies": vendored_transitive_dependencies,
        },
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"dependency audit report {key} does not match release")
    policy = load_policy(policy_path)
    inputs = report.get("inputs")
    if inputs != {
        "policy_sha256": hash_file(policy_path),
        "sbom_sha256": hash_file(sbom_path),
    }:
        raise ValueError("dependency audit input hashes do not match release")
    evaluated_value = report.get("evaluated_on")
    try:
        evaluated_on = date.fromisoformat(evaluated_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("dependency audit evaluation date is invalid") from exc
    scanner = report.get("scanner")
    if not isinstance(scanner, dict):
        raise ValueError("dependency audit scanner metadata is missing")
    platform = scanner.get("platform")
    if not isinstance(platform, str):
        raise ValueError("dependency audit scanner platform is missing")
    expected_scanner = expected_scanner_metadata(policy, platform)
    if scanner != expected_scanner:
        raise ValueError("dependency audit scanner metadata does not match policy")
    findings = report.get("findings")
    summary = report.get("summary")
    if not isinstance(findings, list) or not isinstance(summary, dict):
        raise ValueError("dependency audit findings and summary are required")
    counts = {
        classification: sum(
            isinstance(finding, dict)
            and finding.get("classification") == classification
            for finding in findings
        )
        for classification in (
            "accepted_exception",
            "blocking",
            "informational",
            "withdrawn",
        )
    }
    if counts["blocking"]:
        raise ValueError("dependency audit report contains blocking findings")
    if summary.get("advisories") != len(findings):
        raise ValueError("dependency audit advisory count is inconsistent")
    if any(summary.get(key) != value for key, value in counts.items()):
        raise ValueError("dependency audit finding counts are inconsistent")
    packages_scanned = summary.get("packages_scanned")
    if (
        not isinstance(packages_scanned, int)
        or isinstance(packages_scanned, bool)
        or packages_scanned <= 0
    ):
        raise ValueError("dependency audit did not scan any packages")
    if packages_scanned != _sbom_package_count(sbom_path):
        raise ValueError(
            "dependency audit package count does not match the release SBOM"
        )
    exceptions = {item["id"]: item for item in policy["exceptions"]}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("dependency audit finding is invalid")
        classification = finding.get("classification")
        if classification not in counts:
            raise ValueError("dependency audit finding classification is invalid")
        package = finding.get("package")
        if not isinstance(package, dict) or not all(
            isinstance(package.get(key), str) and package[key]
            for key in ("ecosystem", "name", "version")
        ):
            raise ValueError("dependency audit finding package is invalid")
        advisory_id = finding.get("id")
        aliases = finding.get("aliases")
        if not isinstance(advisory_id, str) or not advisory_id:
            raise ValueError("dependency audit finding identifier is invalid")
        if not isinstance(aliases, list) or not all(
            isinstance(value, str) and value for value in aliases
        ):
            raise ValueError("dependency audit finding aliases are invalid")
        if classification != "accepted_exception":
            continue
        exception_ref = finding.get("exception")
        if not isinstance(exception_ref, dict):
            raise ValueError("dependency audit exception reference is missing")
        exception = exceptions.get(exception_ref.get("id"))
        if exception is None or exception_ref.get("expires") != exception["expires"]:
            raise ValueError("dependency audit exception does not match policy")
        if package != {
            "ecosystem": exception["ecosystem"],
            "name": exception["package"],
            "version": exception["version"],
        }:
            raise ValueError("dependency audit exception package does not match policy")
        if not {advisory_id, *aliases}.intersection(exception["advisories"]):
            raise ValueError(
                "dependency audit exception advisory does not match policy"
            )
        if evaluated_on > date.fromisoformat(exception["expires"]):
            raise ValueError("dependency audit report uses an expired exception")
    return {
        "advisories": len(findings),
        "accepted_exceptions": counts["accepted_exception"],
        "informational": counts["informational"],
        "packages_scanned": packages_scanned,
        "scanner_version": scanner["version"],
    }


def validate_audit_report_file(
    *,
    report_path: Path,
    policy_path: Path,
    sbom_path: Path,
    source_commit: str,
    target: str,
    vendored_transitive_dependencies: str = "top-level-only",
) -> dict:
    report = _read_json_object(report_path, "dependency audit report")
    return validate_audit_report(
        report,
        policy_path=policy_path,
        sbom_path=sbom_path,
        source_commit=source_commit,
        target=target,
        vendored_transitive_dependencies=vendored_transitive_dependencies,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch-scanner")
    fetch.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    fetch.add_argument("--platform", required=True)
    fetch.add_argument("--output", required=True, type=Path)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--scanner", required=True, type=Path)
    scan.add_argument("--platform", required=True)
    scan.add_argument("--sbom", required=True, type=Path)
    scan.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    scan.add_argument("--source-commit", required=True)
    scan.add_argument("--target", required=True)
    scan.add_argument("--evaluation-date", required=True, type=date.fromisoformat)
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument(
        "--vendored-transitive-dependencies",
        choices=VENDORED_TRANSITIVE_COVERAGE,
        default="top-level-only",
    )

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", required=True, type=Path)
    verify.add_argument("--sbom", required=True, type=Path)
    verify.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument(
        "--vendored-transitive-dependencies",
        choices=VENDORED_TRANSITIVE_COVERAGE,
        default="top-level-only",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "fetch-scanner":
        result = fetch_scanner(
            policy_path=args.policy,
            platform=args.platform,
            output=args.output,
        )
    elif args.command == "scan":
        policy = load_policy(args.policy)
        scanner = verify_scanner(
            scanner_path=args.scanner,
            policy=policy,
            platform=args.platform,
        )
        osv_result = run_osv_scan(scanner_path=args.scanner, sbom_path=args.sbom)
        report = build_audit_report(
            osv_result=osv_result,
            policy=policy,
            policy_path=args.policy,
            sbom_path=args.sbom,
            scanner=scanner,
            source_commit=args.source_commit,
            target=args.target,
            evaluated_on=args.evaluation_date,
            vendored_transitive_dependencies=args.vendored_transitive_dependencies,
        )
        write_json_atomic(args.output, report)
        result = report["summary"] | {"status": report["status"]}
        if report["status"] != "pass":
            print(json.dumps(result, sort_keys=True))
            return 1
    else:
        result = validate_audit_report_file(
            report_path=args.report,
            policy_path=args.policy,
            sbom_path=args.sbom,
            source_commit=args.source_commit,
            target=args.target,
            vendored_transitive_dependencies=args.vendored_transitive_dependencies,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

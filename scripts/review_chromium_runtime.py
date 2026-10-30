#!/usr/bin/env python3
"""Collect a proposed Chromium pin on disposable CI; never update production pins."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import materialize_chromium_headless_shell as materializer
import dependency_audit

VERSION = "156.0.8078.80"
REVISION = "1706539"
LENGTH = 103_982_159
GENERATION = "1793229146450866"
MD5_BASE64 = "CoXYkEUVQe/FQAUIeHtb8Q=="
OBJECT = f"{VERSION}/mac-arm64/chrome-headless-shell-mac-arm64.zip"
ARCHIVE_URL = f"https://storage.googleapis.com/chrome-for-testing-public/{OBJECT}"
CATALOG_URL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
VERSION_URL = f"https://googlechromelabs.github.io/chrome-for-testing/{VERSION}.json"
METADATA_URL = "https://storage.googleapis.com/storage/v1/b/chrome-for-testing-public/o/" + urllib.parse.quote(OBJECT, safe="")
MAX_JSON = 1_048_576
MAX_UNPACKED = 1_073_741_824
MARKER = "slipstream-chromium-review-156-dom-ready"


class RuntimeProbeError(ValueError):
    def __init__(self, message: str, evidence: dict):
        super().__init__(message)
        self.evidence = evidence


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_disposable_ci() -> None:
    if not (
        os.environ.get("CI") == "true"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
        and platform.system() == "Darwin"
        and platform.machine() == "arm64"
    ):
        raise ValueError("runtime review requires a GitHub-hosted macOS arm64 PR runner")


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=20, context=materializer._download_tls_context()) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("unexpected upstream JSON response or redirect")
        raw = response.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise ValueError("upstream JSON exceeds size budget")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("upstream JSON is not an object")
    return result


def validate_catalogs(catalog: dict, version: dict, metadata: dict) -> None:
    stable = catalog.get("channels", {}).get("Stable", {})
    for entry in (stable, version):
        if entry.get("version") != VERSION or entry.get("revision") != REVISION:
            raise ValueError("official version/revision differs from reviewed candidate")
        downloads = entry.get("downloads", {}).get("chrome-headless-shell", [])
        arm = [item for item in downloads if item.get("platform") == "mac-arm64"]
        if len(arm) != 1 or arm[0].get("url") != ARCHIVE_URL:
            raise ValueError("official mac-arm64 archive identity differs")
    expected = {"name": OBJECT, "size": str(LENGTH), "generation": GENERATION, "md5Hash": MD5_BASE64}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("official object metadata differs from reviewed candidate")


def copy_archive(response: object, destination: Path) -> dict:
    if response.status != 200 or response.geturl() != ARCHIVE_URL:
        raise ValueError("unexpected archive response or redirect")
    if response.headers.get("Content-Length") != str(LENGTH):
        raise ValueError("archive response length differs")
    if response.headers.get("x-goog-generation") != GENERATION:
        raise ValueError("archive response generation differs")
    sha256, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    length = 0
    deadline = time.monotonic() + 240
    with destination.open("wb") as output:
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("archive transfer exceeded deadline")
            block = response.read(1_048_576)
            if not block:
                break
            length += len(block)
            if length > LENGTH:
                raise ValueError("archive transfer exceeded size budget")
            output.write(block)
            sha256.update(block)
            md5.update(block)
    if length != LENGTH or base64.b64encode(md5.digest()).decode() != MD5_BASE64:
        raise ValueError("archive transfer does not match official length/MD5")
    return {"url": ARCHIVE_URL, "length": length, "sha256": sha256.hexdigest()}


def validate_zip_budget(archive: Path) -> None:
    """Bound extraction before handing the archive to the production materializer."""
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > 4096 or sum(item.file_size for item in entries) > MAX_UNPACKED:
            raise ValueError("archive extraction exceeds budget")
        names = set()
        for item in entries:
            name = item.filename.rstrip("/")
            path = PurePosixPath(name)
            mode = item.external_attr >> 16
            if (
                name in names or not name or item.orig_filename != item.filename
                or path.is_absolute() or ".." in path.parts or path.as_posix() != name
                or path.parts[0] != "chrome-headless-shell-mac-arm64"
                or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                or item.flag_bits & 1
            ):
                raise ValueError("unsafe or duplicate archive entry")
            names.add(name)


def materialize_proposal(archive: Path, runtime: Path, proposal: dict, proposal_path: Path) -> dict:
    write_json(proposal_path, proposal)
    previous_source = materializer.SOURCE
    try:
        materializer.SOURCE = proposal_path
        return materializer.materialize(runtime, archive)
    finally:
        materializer.SOURCE = previous_source


def group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def stop_group(process: subprocess.Popen) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not group_exists(process.pid):
            process.wait(timeout=2)
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            process.poll()  # Reap our child before checking group disappearance.
            if not group_exists(process.pid):
                return
            time.sleep(0.05)
    raise ValueError("owned Chromium process group did not disappear")


def run_owned(command: list[str], temporary: Path, label: str, timeout: int) -> dict:
    stdout, stderr = temporary / f"{label}.stdout", temporary / f"{label}.stderr"
    failure = None
    returncode = None
    group_absent = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            failure = "deadline exceeded"
        finally:
            try:
                stop_group(process)
                group_absent = True
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                failure = f"owned cleanup failed: {type(exc).__name__}"
    if stdout.stat().st_size > 65536 or stderr.stat().st_size > 65536:
        failure = failure or "output exceeds budget"
    result = {"label": label, "returncode": returncode, "owned_process_group_absent": group_absent}
    for name, path in (("stdout", stdout), ("stderr", stderr)):
        with path.open("rb") as stream:
            result[name] = stream.read(65536).decode("utf-8", errors="replace")
    if failure or returncode != 0:
        raise RuntimeProbeError(f"runtime {label}: {failure or 'nonzero exit'}", result)
    return result


def smoke_arguments(executable: Path, profile: Path) -> list[str]:
    html = f"<html><body><script>document.body.textContent='{MARKER}'</script></body></html>"
    return [str(executable), "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
            "--disable-sync", "--disable-extensions", "--host-resolver-rules=MAP * ~NOTFOUND",
            f"--user-data-dir={profile}", "--dump-dom", "data:text/html," + urllib.parse.quote(html)]


def mapping_spdx(proposal: dict) -> dict:
    package_id = "SPDXRef-ChromiumCandidate"
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Slipstream candidate Chromium mapping fixture (not a complete application SBOM)",
        "documentNamespace": f"https://spdx.org/spdxdocs/slipstream-chromium-review-{VERSION}-{proposal['archive']['sha256']}",
        "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": ["Tool: slipstream-chromium-runtime-review"]},
        "documentDescribes": [package_id],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": package_id}],
        "packages": [{
            "SPDXID": package_id, "name": "chromium-headless-shell", "versionInfo": VERSION,
            "downloadLocation": ARCHIVE_URL, "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION", "primaryPackagePurpose": "APPLICATION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": proposal["archive"]["sha256"]}],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": f"pkg:generic/chromium-headless-shell@{VERSION}"}],
        }],
    }


def classify_osv_mapping(result: dict) -> dict:
    results = result.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV mapping lacks results")
    entries = []
    for source in results:
        if not isinstance(source, dict) or not isinstance(source.get("packages"), list):
            raise ValueError("OSV mapping has malformed package source")
        entries.extend(source["packages"])
    if len(entries) != 1 or not isinstance(entries[0], dict):
        raise ValueError("OSV mapping must retain exactly one candidate package")
    entry = entries[0]
    identity = {"ecosystem": "", "name": "chromium-headless-shell", "version": VERSION}
    package = entry.get("package")
    if not isinstance(package, dict) or any(package.get(key) != value for key, value in identity.items()):
        raise ValueError("OSV candidate identity or ecosystem mapping differs; review required")
    vulnerabilities = entry.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("OSV mapping vulnerabilities is not a list")
    if vulnerabilities or entry.get("groups") or entry.get("vulnerability_groups") or result.get("vulnerabilities"):
        raise ValueError("OSV reported candidate vulnerabilities")
    return {"classification": "unsupported_unscannable_empty_ecosystem", "package": identity,
            "vulnerability_coverage": False, "security_passed": False,
            "interpretation": "The generic candidate identity is retained without an ecosystem; absence of reported findings is not vulnerability clearance."}


def review_osv_mapping(work: Path, output: Path, proposal: dict) -> dict:
    """Use policy only to authenticate the scanner, never to admit Chromium."""
    policy_path = dependency_audit.DEFAULT_POLICY
    policy = dependency_audit.load_policy(policy_path)
    scanner = work / "osv-scanner"
    downloaded = dependency_audit.fetch_scanner(policy_path=policy_path, platform="darwin-arm64", output=scanner)
    verified = dependency_audit.verify_scanner(scanner_path=scanner, policy=policy, platform="darwin-arm64")
    scanner_receipt = {"download": downloaded, "verified": verified,
                       "policy_used_for": "scanner identity only; no integrity-only admission or expiry exception",
                       "policy_sha256": materializer._hash(policy_path)}
    write_json(output / "osv-scanner-metadata.json", scanner_receipt)
    sbom = output / "chromium-mapping.spdx.json"
    write_json(sbom, mapping_spdx(proposal))
    result = dependency_audit.run_osv_scan(scanner_path=scanner, sbom_path=sbom)
    if len(json.dumps(result).encode("utf-8")) > MAX_JSON:
        raise ValueError("one-package OSV result exceeds evidence budget")
    result_path = output / "osv-result.json"
    write_json(result_path, result)  # Preserve the parsed scanner result, also on classification failure.
    mapping = classify_osv_mapping(result)
    mapping.update({"scanner": scanner_receipt, "input_sha256": materializer._hash(sbom),
                    "output_sha256": materializer._hash(result_path),
                    "input": sbom.name, "output": result_path.name})
    write_json(output / "osv-mapping.json", mapping)
    return mapping


def review(output: Path) -> dict:
    require_disposable_ci()  # Before any network request or subprocess.
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema_version": 1, "status": "pending", "version": VERSION, "revision": REVISION,
               "reviewed_at": datetime.now(timezone.utc).isoformat(), "integrity_only": True,
               "vulnerability_coverage": "not assessed by this artifact review",
               "production_pins_updated": False,
               "ci": {key: os.environ.get(key, "") for key in (
                   "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
                   "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ENVIRONMENT")}}
    try:
        catalog, version, metadata = (fetch_json(url) for url in (CATALOG_URL, VERSION_URL, METADATA_URL))
        validate_catalogs(catalog, version, metadata)
        for name, value in (("catalog", catalog), ("version", version), ("metadata", metadata)):
            write_json(output / f"{name}.json", value)
        with tempfile.TemporaryDirectory(prefix="slipstream-chromium-review-") as temporary:
            work = Path(temporary)
            archive = work / "runtime.zip"
            with urllib.request.urlopen(ARCHIVE_URL, timeout=20, context=materializer._download_tls_context()) as response:
                contract = copy_archive(response, archive)
            validate_zip_budget(archive)
            proposal = {"archive": contract, "component": "Chrome for Testing chrome-headless-shell",
                        "license_path": "LICENSE.headless_shell", "platform": "mac-arm64", "version": VERSION}
            runtime = work / "runtime"
            manifest = materialize_proposal(archive, runtime, proposal, work / "proposed-SOURCE.json")
            write_json(output / "proposed-SOURCE.json", proposal)
            write_json(output / "manifest.json", manifest)
            executable = runtime / "chrome-headless-shell"
            architecture = subprocess.run(["/usr/bin/lipo", "-archs", str(executable)], capture_output=True,
                                          text=True, check=True, timeout=10).stdout.strip()
            if architecture != "arm64":
                raise ValueError("candidate executable is not exclusively arm64")
            version_result = run_owned([str(executable), "--version"], work, "version", 10)
            if not re.search(rf"(?<![\d.]){re.escape(VERSION)}(?![\d.])", version_result["stdout"]):
                raise ValueError("candidate executable version differs")
            smoke = run_owned(smoke_arguments(executable, work / "profile"), work, "dom", 35)
            if f"<body>{MARKER}</body>" not in smoke["stdout"]:
                raise ValueError("sandbox DOM smoke did not execute the local script")
            documents = {}
            for name in ("LICENSE.headless_shell", "ABOUT"):
                path = runtime / name
                if path.stat().st_size == 0:
                    raise ValueError("candidate upstream document is empty")
                with path.open("rb") as stream:
                    preview = stream.read(4096).decode("utf-8", errors="replace")
                documents[name] = {"length": path.stat().st_size, "sha256": materializer._hash(path), "preview": preview}
            write_json(output / "upstream-documents.json", documents)
            receipt.update({"archive": contract, "generation": GENERATION, "architecture": architecture,
                            "manifest": manifest, "version_smoke": version_result, "dom_smoke": smoke,
                            "sandbox_disabled": False, "navigation": "synthetic data URL only"})
            receipt["osv_mapping"] = review_osv_mapping(work, output, proposal)
            receipt["vulnerability_coverage"] = "unsupported/unscannable generic package; no vulnerability clearance"
        receipt.update({"status": "pass", "temporary_runtime_profile_archive_removed": not work.exists()})
        return receipt
    except Exception as exc:
        receipt.update({"status": "fail", "error_class": type(exc).__name__, "error": str(exc)[:512]})
        if isinstance(exc, RuntimeProbeError):
            receipt["runtime_failure"] = exc.evidence
        raise
    finally:
        write_json(output / "receipt.json", receipt)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = review(args.output)
    print(json.dumps({"status": result["status"], "version": VERSION, "archive": result["archive"]}))


if __name__ == "__main__":
    main()

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import review_chromium_runtime as review


class Response(io.BytesIO):
    status = 200

    def __init__(self, content: bytes, url: str, headers: dict | None = None):
        super().__init__(content)
        self.url = url
        self.headers = headers or {}

    def geturl(self) -> str:
        return self.url


class ChromiumRuntimeReviewTests(unittest.TestCase):
    def osv_result(self) -> dict:
        return {"results": [{"source": {"type": "lockfile", "path": "chromium-mapping.spdx.json"},
                             "packages": [{"package": {"ecosystem": "", "name": "chromium-headless-shell",
                                                        "version": review.VERSION}}]}]}

    def catalogs(self) -> tuple[dict, dict, dict]:
        version = {"version": review.VERSION, "revision": review.REVISION,
                   "downloads": {"chrome-headless-shell": [{"platform": "mac-arm64", "url": review.ARCHIVE_URL}]}}
        metadata = {"name": review.OBJECT, "size": str(review.LENGTH),
                    "generation": review.GENERATION, "md5Hash": review.MD5_BASE64}
        return {"channels": {"Stable": copy.deepcopy(version)}}, version, metadata

    def test_official_catalogs_agree(self) -> None:
        review.validate_catalogs(*self.catalogs())

    def test_catalog_version_revision_url_and_generation_drift_reject(self) -> None:
        for field in ("version", "revision", "url", "generation"):
            with self.subTest(field=field):
                catalog, version, metadata = self.catalogs()
                if field == "url":
                    version["downloads"]["chrome-headless-shell"][0]["url"] = "https://example.invalid/runtime.zip"
                elif field == "generation":
                    metadata[field] = "other-generation"
                else:
                    version[field] = "unexpected"
                with self.assertRaises(ValueError):
                    review.validate_catalogs(catalog, version, metadata)

    def test_duplicate_architecture_entry_rejects(self) -> None:
        catalog, version, metadata = self.catalogs()
        version["downloads"]["chrome-headless-shell"] *= 2
        with self.assertRaises(ValueError):
            review.validate_catalogs(catalog, version, metadata)

    def test_guard_rejects_workstation_before_network(self) -> None:
        with mock.patch.dict(review.os.environ, {}, clear=True), mock.patch.object(review, "fetch_json") as fetch:
            with self.assertRaisesRegex(ValueError, "GitHub-hosted"):
                review.review(Path("unused-review-output"))
            fetch.assert_not_called()

    def test_json_size_limit_and_redirect_reject(self) -> None:
        for content, url in ((b"x" * 30, review.CATALOG_URL), (b"{}", "https://example.invalid/")):
            with self.subTest(url=url), mock.patch.object(review, "MAX_JSON", 20), \
                    mock.patch.object(review.urllib.request, "urlopen", return_value=Response(content, url)):
                with self.assertRaises(ValueError):
                    review.fetch_json(review.CATALOG_URL)

    def copy_fixture(self, content: bytes, body: bytes | None = None, generation: str | None = None) -> dict:
        digest = base64.b64encode(hashlib.md5(content, usedforsecurity=False).digest()).decode()
        headers = {"Content-Length": str(len(content)), "x-goog-generation": generation or review.GENERATION}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(review, "LENGTH", len(content)), mock.patch.object(review, "MD5_BASE64", digest):
            return review.copy_archive(Response(content if body is None else body, review.ARCHIVE_URL, headers),
                                       Path(temporary) / "candidate.zip")

    def test_archive_stream_receipt_hash(self) -> None:
        result = self.copy_fixture(b"complete reviewed archive")
        self.assertEqual(result["sha256"], hashlib.sha256(b"complete reviewed archive").hexdigest())
        self.assertEqual(result["length"], len(b"complete reviewed archive"))

    def test_archive_short_oversized_corrupt_and_replaced_fail(self) -> None:
        for body, generation in ((b"ab", None), (b"abcd", None), (b"abd", None), (b"abc", "new")):
            with self.subTest(body=body, generation=generation), self.assertRaises(ValueError):
                self.copy_fixture(b"abc", body, generation)

    def test_archive_deadline_rejects(self) -> None:
        with mock.patch.object(review.time, "monotonic", side_effect=[0, 241]), \
                self.assertRaisesRegex(ValueError, "deadline"):
            self.copy_fixture(b"abc")

    def test_zip_rejects_traversal_symlink_duplicate_and_size(self) -> None:
        prefix = "chrome-headless-shell-mac-arm64/"
        cases = ("traversal", "symlink", "duplicate", "size")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "archive.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    if case == "traversal":
                        bundle.writestr(prefix + "../escape", "bad")
                    elif case == "symlink":
                        entry = zipfile.ZipInfo(prefix + "link")
                        entry.create_system = 3
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                        bundle.writestr(entry, "/tmp/elsewhere")
                    elif case == "duplicate":
                        bundle.writestr(prefix + "dir", "data")
                        bundle.writestr(prefix + "dir/", "")
                    else:
                        bundle.writestr(prefix + "data", "too large")
                with mock.patch.object(review, "MAX_UNPACKED", 2 if case == "size" else 1000), \
                        self.assertRaises(ValueError):
                    review.validate_zip_budget(archive)

    def test_materializer_reuses_validation_and_restores_original_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                for name in ("chrome-headless-shell", "ABOUT", "LICENSE.headless_shell"):
                    bundle.writestr("chrome-headless-shell-mac-arm64/" + name, b"fixture")
            review.validate_zip_budget(archive)
            proposal = {"archive": {"url": review.ARCHIVE_URL, "length": archive.stat().st_size,
                                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
                        "component": "Chrome for Testing chrome-headless-shell", "platform": "mac-arm64",
                        "version": review.VERSION, "license_path": "LICENSE.headless_shell"}
            source = review.materializer.SOURCE
            manifest = review.materialize_proposal(archive, root / "runtime", proposal, root / "source.json")
            self.assertEqual(manifest["version"], review.VERSION)
            self.assertEqual(review.materializer.SOURCE, source)
            proposal["archive"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                review.materialize_proposal(archive, root / "other", proposal, root / "bad-source.json")
            self.assertEqual(review.materializer.SOURCE, source)

    def test_smoke_is_sandboxed_synthetic_script_with_private_profile(self) -> None:
        args = review.smoke_arguments(Path("/runtime/chrome-headless-shell"), Path("/temporary/profile"))
        self.assertNotIn("--no-sandbox", args)
        self.assertIn("--user-data-dir=/temporary/profile", args)
        self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND", args)
        self.assertTrue(args[-1].startswith("data:text/html,"))
        self.assertIn("document.body.textContent", review.urllib.parse.unquote(args[-1]))

    def test_smoke_deadline_still_runs_owned_cleanup(self) -> None:
        process = mock.Mock()
        process.wait.side_effect = review.subprocess.TimeoutExpired("fixture", 1)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(review.subprocess, "Popen", return_value=process), \
                mock.patch.object(review, "stop_group") as cleanup:
            with self.assertRaises(review.RuntimeProbeError) as raised:
                review.run_owned(["never-executed-fixture"], Path(temporary), "timeout", 1)
            cleanup.assert_called_once_with(process)
            self.assertTrue(raised.exception.evidence["owned_process_group_absent"])
            self.assertIn("deadline", str(raised.exception))

    def test_osv_retained_unmapped_identity_is_not_security_clearance(self) -> None:
        mapping = review.classify_osv_mapping(self.osv_result())
        self.assertEqual(mapping["classification"], "unsupported_unscannable_empty_ecosystem")
        self.assertFalse(mapping["security_passed"])
        self.assertFalse(mapping["vulnerability_coverage"])

    def test_osv_absent_changed_duplicate_or_vulnerable_identity_rejects(self) -> None:
        for case in ("absent", "name", "version", "ecosystem", "duplicate", "vulnerability", "malformed"):
            with self.subTest(case=case):
                result = self.osv_result()
                packages = result["results"][0]["packages"]
                if case == "absent":
                    packages.clear()
                elif case == "duplicate":
                    packages.append(copy.deepcopy(packages[0]))
                elif case in ("name", "version", "ecosystem"):
                    packages[0]["package"][case] = "unexpected"
                else:
                    packages[0]["vulnerabilities"] = [{"id": "CVE-fixture"}] if case == "vulnerability" else None
                with self.assertRaises(ValueError):
                    review.classify_osv_mapping(result)

    def test_osv_same_job_saves_exact_fixture_output_and_verified_scanner_without_admission(self) -> None:
        proposal = {"archive": {"sha256": "f" * 64}}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(review.dependency_audit, "fetch_scanner", return_value={"sha256": "a" * 64}) as fetch, \
                mock.patch.object(review.dependency_audit, "verify_scanner", return_value={"version": "2.3.8"}) as verify, \
                mock.patch.object(review.dependency_audit, "run_osv_scan", return_value=self.osv_result()) as scan, \
                mock.patch.object(review.dependency_audit, "evaluate_osv_result", side_effect=AssertionError("must not admit old policy")):
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            mapping = review.review_osv_mapping(root, output, proposal)
            fetch.assert_called_once()
            verify.assert_called_once()
            scan.assert_called_once()
            document = json.loads((output / "chromium-mapping.spdx.json").read_text())
            self.assertEqual(len(document["packages"]), 1)
            self.assertEqual(document["packages"][0]["checksums"][0]["checksumValue"], "f" * 64)
            self.assertEqual(document["packages"][0]["versionInfo"], review.VERSION)
            self.assertEqual(json.loads((output / "osv-result.json").read_text()), self.osv_result())
            self.assertEqual(mapping["input_sha256"], review.materializer._hash(output / "chromium-mapping.spdx.json"))
            self.assertFalse(mapping["security_passed"])


if __name__ == "__main__":
    unittest.main()

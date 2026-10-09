from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import chromium_advisory_audit as audit

NOW = datetime(2026, 10, 9, 17, tzinfo=timezone.utc)
FIXED = "155.0.8059.39"


def record(ident="CVE-2026-106358"):
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"cveId": ident, "state": "PUBLISHED", "assignerOrgId": audit.CHROME_CNA},
            "containers": {"cna": {"providerMetadata": {"orgId": audit.CHROME_CNA},
                "descriptions": [{"lang": "en", "value": f"Use after free in Google Chrome prior to {FIXED} allowed execution."}],
                "affected": [{"vendor": "Google", "product": "Chrome", "versions": [
                    {"version": FIXED, "lessThan": FIXED, "versionType": "custom", "status": "affected"}]}]}}}


class ChromiumAuditTests(unittest.TestCase):
    def fixture(self, root: Path, records=None, nested=False):
        source = {"component": "Chrome for Testing chrome-headless-shell", "platform": "mac-arm64",
                  "version": FIXED, "license_path": "LICENSE.headless_shell", "archive": {
                      "url": f"https://storage.googleapis.com/chrome-for-testing-public/{FIXED}/mac-arm64/chrome-headless-shell-mac-arm64.zip",
                      "length": 100, "sha256": "a" * 64}}
        cft = {"timestamp": NOW.isoformat(), "channels": {"Stable": {"channel": "Stable", "version": FIXED,
               "revision": "1697595", "downloads": {"chrome-headless-shell": [
                   {"platform": "mac-arm64", "url": source["archive"]["url"]}]}}}}
        feed = {"feed": {"id": {"$t": "tag:blogger.com,1999:blog-8982037438137564684"},
                "updated": {"$t": NOW.isoformat()}, "openSearch$startIndex": {"$t": "1"}, "entry": [{
                    "title": {"$t": "Stable Channel Update for Desktop"}, "published": {"$t": NOW.isoformat()},
                    "link": [{"rel": "alternate", "type": "text/html", "href": "https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop.html"}],
                    "content": {"$t": f"<p>{FIXED}. This update includes <b>1</b> security fixes. CVE-2026-106358</p>"}}]}}
        archive = root / "baseline.zip"
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as z:
            for r in records if records is not None else [record()]:
                z.writestr(f"cves/2026/106xxx/{r['cveMetadata']['cveId']}.json", json.dumps(r))
            z.writestr("cves/delta.json", "{}")
            z.writestr("cves/deltaLog.json", "{}")
        if nested:
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("cves.zip", payload.getvalue())
        else:
            archive.write_bytes(payload.getvalue())
        name = "2026-10-09_all_CVEs_at_midnight.zip.zip"; tag = "cve_2026-10-09_1600Z"
        release = {"tag_name": tag, "draft": False, "prerelease": False, "published_at": NOW.isoformat(),
                   "assets": [{"name": name, "browser_download_url": f"https://github.com/CVEProject/cvelistV5/releases/download/{tag}/{name}",
                               "size": archive.stat().st_size, "digest": "sha256:" + audit.digest(archive)}]}
        result = {"baseline": archive}
        for key, value in {"source": source, "cft": cft, "feed": feed, "release": release}.items():
            path = root / f"{key}.json"; path.write_text(json.dumps(value)); result[key] = path
        return result

    def test_complete_snapshot_binds_exact_headless_archive(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as tmp:
                inputs = self.fixture(Path(tmp), nested=nested)
                report = audit.audit(**inputs, now=NOW)
                self.assertEqual(report["evaluation_status"], "pass")
                self.assertEqual(report["status"], "fail")  # Caller-supplied metadata is not origin proof.
                self.assertEqual(report["provenance"], "unverified-local-inputs")
                self.assertEqual(report["summary"]["catalogue_records"], 1)
                self.assertEqual(report["artifact"]["purl"], f"pkg:generic/chromium-headless-shell@{FIXED}")
                self.assertEqual(report["artifact"]["revision"], "1697595")

    def test_old_version_affected_fixed_boundary_unaffected(self):
        self.assertEqual(audit.evaluate_record(record(), "151.0.7922.77"), "affected")
        self.assertEqual(audit.evaluate_record(record(), FIXED), "not_affected")

    def test_platform_description_does_not_exclude_headless(self):
        for platform in ("Windows", "Linux, Mac, ChromeOS"):
            r = record(); r["containers"]["cna"]["descriptions"][0]["value"] = f"Bug in Google Chrome on {platform} prior to {FIXED} allows execution."
            self.assertEqual(audit.evaluate_record(r, "151.0.7922.77"), "affected")

    def test_prior_to_with_unspecified_lower_bound_is_conservative(self):
        r = record(); r["containers"]["cna"]["affected"][0]["versions"][0]["version"] = "unspecified"
        self.assertEqual(audit.evaluate_record(r, "151.0.7922.77"), "affected")
        self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")

    def test_legacy_version_sentence_requires_identical_explicit_boundary(self):
        r = record(); cna = r["containers"]["cna"]
        cna["affected"][0]["versions"] = [{"status": "affected", "version": f"Google Chrome prior to {FIXED} for Windows"}]
        self.assertEqual(audit.evaluate_record(r, "151.0.7922.77"), "affected")
        self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")
        cna["affected"][0]["versions"][0]["version"] = f"prior to {FIXED}"
        self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")
        cna["affected"][0]["versions"][0]["version"] += " or earlier and after 156.0.0.0"
        self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_explicit_major_milestone_boundary(self):
        for milestone in ("M155", "155"):
            r = record(); cna = r["containers"]["cna"]
            cna["descriptions"][0]["value"] = f"Google Chrome before {milestone} allows execution."
            cna["affected"][0]["versions"] = [{"status": "affected", "version": "n/a"}]
            self.assertEqual(audit.evaluate_record(r, "154.0.0.1"), "affected")
            self.assertEqual(audit.evaluate_record(r, "155.0.0.0"), "not_affected")
            cna["descriptions"][0]["value"] = "Google Chrome before M155.7 has an undocumented range."
            self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_ambiguous_major_platform_or_open_ended_suffix_never_passes(self):
        for description in ("Google Chrome prior to M155 on Windows and M156 on Mac allows execution.",
                            "Google Chrome prior to 155 on Windows and 156 on Mac allows execution.",
                            "Google Chrome prior to M155 allowed execution on Windows and prior to M156 on Mac.",
                            "Google Chrome prior to 155 allowed execution on Windows and prior to 156 on Mac.",
                            f"Google Chrome prior to {FIXED} and all later versions allows execution."):
            with self.subTest(description=description):
                r = record(); cna = r["containers"]["cna"]
                cna["descriptions"][0]["value"] = description
                cna["affected"][0]["versions"] = [{"status": "affected", "version": "n/a"}]
                self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_legacy_fault_clauses_preserve_explicit_chrome_boundaries(self):
        # Description/affected-field projections of the retained official CVEs;
        # no ID allowlist and no component or platform exemption.
        cases = [
            ("CVE-2015-8480", "47.0.2526.73", "The VideoFramePool::PoolImpl::CreateFrame function in media/base/video_frame_pool.cc in Google Chrome before 47.0.2526.73 does not initialize memory for a video-frame data structure, which might allow remote attackers to cause a denial of service (out-of-bounds memory access) or possibly have unspecified other impact by leveraging improper interaction with the vp3_h_loop_filter_c function in libavcodec/vp3dsp.c in FFmpeg.", "n/a"),
            ("CVE-2015-1271", "44.0.2403.89", "PDFium, as used in Google Chrome before 44.0.2403.89, does not properly handle certain out-of-memory conditions, which allows remote attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via a crafted PDF document that triggers a large memory allocation.", "n/a"),
            ("CVE-2013-2848", "27.0.1453.93", "The XSS Auditor in Google Chrome before 27.0.1453.93 might allow remote attackers to obtain sensitive information via unspecified vectors.", "n/a"),
            ("CVE-2017-5025", "56.0.2924.76", "FFmpeg in Google Chrome prior to 56.0.2924.76 for Linux, Windows and Mac, failed to perform proper bounds checking, which allowed a remote attacker to potentially exploit heap corruption via a crafted video file.", "Google Chrome prior to 56.0.2924.76 for Linux, Windows and Mac"),
            ("CVE-2016-1664", "50.0.2661.94", "The HistoryController::UpdateForCommit function in content/renderer/history_controller.cc in Google Chrome before 50.0.2661.94 mishandles the interaction between subframe forward navigations and other forward navigations, which allows remote attackers to spoof the address bar via a crafted web site.", "n/a"),
        ]
        for ident, boundary, description, legacy in cases:
            with self.subTest(cve=ident):
                r = record(ident); cna = r["containers"]["cna"]
                cna["descriptions"][0]["value"] = description
                cna["affected"] = [{"product": legacy, "vendor": "n/a", "versions": [{"status": "affected", "version": legacy}]}]
                self.assertEqual(audit.evaluate_record_detail(r, "0.0.0.0"), ("affected", "explicit-fixed-boundary:" + boundary))
                self.assertEqual(audit.evaluate_record(r, boundary), "not_affected")
                self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")

    def test_legacy_clause_extensions_reject_qualifications_and_extra_versions(self):
        for suffix in ("; Chrome 156 remains affected.", " in subsequent releases.",
                       " and all later Chrome builds.", " in future milestones.",
                       " in FFmpeg 2.4.6.", " except on Mac.", " in version 156.",
                       " on Mac earlier than 156.", " and M156 on Mac.",
                       " and 156 has the same defect.", " in Chrome 155.",
                       " from M156 onward.", "; the same defect persists starting with 156.",
                       ", including M156.", ", with affected builds extending beyond M156.",
                       " using 16 byte packets."):
            for clause in ("allowed execution", "does not properly check bounds"):
                with self.subTest(suffix=suffix, clause=clause):
                    r = record(); cna = r["containers"]["cna"]
                    cna["descriptions"][0]["value"] = "Google Chrome before 155 " + clause + suffix
                    cna["affected"][0]["versions"] = [{"status": "affected", "version": "n/a"}]
                    self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")
        for malformed in ("Google Chrome before 155, , allowed execution.",
                          "Google Chrome before 155, , does not properly check bounds.",
                          "Google Chrome before 155 does not properly xyzzy.",
                          "Google Chrome before 155, when optional mode is used, does not properly check bounds.",
                          "Google Chrome before 155 and other products, does not properly check bounds."):
            with self.subTest(malformed=malformed):
                r = record(); r["containers"]["cna"]["descriptions"][0]["value"] = malformed
                r["containers"]["cna"]["affected"][0]["versions"] = [{"status": "affected", "version": "n/a"}]
                self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_cve_reference_digits_are_not_an_extra_version(self):
        r = record(); cna = r["containers"]["cna"]
        cna["descriptions"][0]["value"] = f"Google Chrome before {FIXED} does not properly check bounds, a different vulnerability than CVE-2015-1231."
        self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")

    def test_v8_engine_identity_is_not_an_extra_version(self):
        for prefix in ("Use after free in V8 in ", "Google V8, as used in ",
                       "V8 API in ", "Type confusion in V8 Turbofan in ",
                       "Use after free in V8 Internationalization in ",
                       "V8 JavaScript engine in "):
            with self.subTest(prefix=prefix):
                r = record(); cna = r["containers"]["cna"]
                cna["descriptions"][0]["value"] = prefix + f"Google Chrome before {FIXED} allowed execution."
                self.assertEqual(audit.evaluate_record(r, "154.0.0.0"), "affected")
                self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")

    def test_v8_context_does_not_hide_versions_or_source_revisions(self):
        for description in (
                "Use after free in version V8 in Google Chrome before 155 allowed execution.",
                "Use after free from v8 onward in Google Chrome before 155 allowed execution.",
                "Use after free in V8 in Google Chrome before 155 allowed execution from v8 onward.",
                "Use after free in V8 in Google Chrome before 155 allowed execution, including V8.",
                "Google V8, as used in Google Chrome before 155 allowed execution in V8 version 15.5.35.21.",
                "V8 API in Google Chrome before 155 allowed execution until r1697596.",
                "Google V8 before r3560, as used in Google Chrome before 155 allowed execution.",
                "Use after free in V8.1 in Google Chrome before 155 allowed execution.",
                "Google Chrome before 155 allowed execution after WebKit r53607.",
                "Google Chrome before 155 allowed execution through R59950."):
            with self.subTest(description=description):
                r = record(); cna = r["containers"]["cna"]
                cna["descriptions"][0]["value"] = description
                cna["affected"][0]["versions"] = [{"status": "affected", "version": "n/a"}]
                self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_legacy_clauses_cannot_skip_product_range_or_adp_guards(self):
        for mutation in (lambda c: c["affected"][0].update(product="FFmpeg"),
                         lambda c: c["affected"][0].update(defaultStatus="affected"),
                         lambda c: c["affected"][0]["versions"][0].update(lessThan="156.0.0.0"),
                         lambda c: c["affected"][0]["versions"][0].update(status="unaffected"),
                         lambda c: c["affected"][0]["versions"][0].update(changes=[])):
            with self.subTest(mutation=mutation):
                r = record(); cna = r["containers"]["cna"]
                cna["descriptions"][0]["value"] = f"Google Chrome before {FIXED} does not properly check bounds."
                mutation(cna)
                self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")
        r = record(); r["containers"]["cna"]["descriptions"][0]["value"] = f"Google Chrome before {FIXED} might allow remote attackers to read data."
        r["containers"]["adp"] = [{"affected": [{"product": "Chrome", "versions": [{"version": "all", "status": "affected"}]}]}]
        self.assertEqual(audit.evaluate_record_detail(r, FIXED), ("unknown", "supplemental-chromium-range-requires-review"))

    def test_missing_product_identity_with_chrome_advisory_never_disappears(self):
        for affected in ([], [{"versions": [{"status": "affected", "version": "n/a"}]}]):
            with self.subTest(affected=affected), tempfile.TemporaryDirectory() as tmp:
                r = record("CVE-2026-106359"); r["cveMetadata"]["assignerOrgId"] = "other"
                cna = r["containers"]["cna"]; cna["providerMetadata"]["orgId"] = "other"
                cna["affected"] = affected
                cna["descriptions"][0]["value"] = "Google Chrome prior to 156.0.0.0 on Mac allows execution."
                report = audit.audit(**self.fixture(Path(tmp), records=[record(), r]), now=NOW)
                self.assertEqual(report["evaluation_status"], "fail")

    def test_supplemental_chromium_ranges_cannot_be_silently_overridden(self):
        for limit in ("156.0.0.0", "110.5481.177"):
            r = record(); r["containers"]["adp"] = [{"affected": [{"product": "chrome", "versions": [
                {"version": "0", "lessThan": limit, "versionType": "custom", "status": "affected"}]}]}]
            self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")
        r["cveMetadata"]["assignerOrgId"] = "other"
        r["containers"]["cna"]["providerMetadata"]["orgId"] = "other"
        r["containers"]["cna"]["affected"][0]["product"] = "Different product"
        self.assertTrue(audit.relevant(r))  # ADP identifies an omitted Chromium product.

    def test_only_owned_primary_metadata_refresh_can_establish_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = self.fixture(root)
            raw = {audit.CFT_URL: paths["cft"].read_bytes(), audit.CVE_RELEASE_URL: paths["release"].read_bytes(),
                   audit.RELEASE_FEED_URL: paths["feed"].read_bytes()}
            with patch.object(audit, "_fetch_metadata", side_effect=lambda url: raw[url]) as fetch:
                report = audit.audit_from_official_metadata(source=paths["source"], baseline=paths["baseline"],
                    evidence_dir=root / "captured", now=NOW)
                self.assertEqual(fetch.call_count, 3)
                self.assertEqual(report["status"], "pass")
                self.assertEqual(report["provenance"], "fresh-fixed-official-HTTPS-metadata")
                self.assertEqual(report["fetched_metadata"]["release"]["sha256"], audit.digest(paths["release"]))
            with self.assertRaisesRegex(ValueError, "unreviewed metadata"):
                audit._fetch_metadata("https://example.com/forged.json")

    def test_refresh_rejects_metadata_replaced_before_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = self.fixture(root); destination = root / "captured"
            raw = {audit.CFT_URL: paths["cft"].read_bytes(), audit.CVE_RELEASE_URL: paths["release"].read_bytes(),
                   audit.RELEASE_FEED_URL: paths["feed"].read_bytes()}
            def fetch(url):
                if url == audit.RELEASE_FEED_URL:
                    cft = json.loads(raw[audit.CFT_URL]); cft["channels"]["Stable"]["revision"] = "7"
                    (destination / "cft.json").write_text(json.dumps(cft))
                return raw[url]
            with patch.object(audit, "_fetch_metadata", side_effect=fetch), self.assertRaisesRegex(ValueError, "changed before evaluation"):
                audit.audit_from_official_metadata(source=paths["source"], baseline=paths["baseline"], evidence_dir=destination, now=NOW)

    def test_fresh_fetch_accepts_unchanged_week_old_release_metadata(self):
        # Content publication/update time is not the time we fetched the current
        # official metadata. Stable legitimately remains unchanged for days.
        for old_fields in (("cft",), ("feed",), ("post",), ("cft", "feed", "post")):
            with self.subTest(old_fields=old_fields), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); paths = self.fixture(root)
                cft = audit.read_json(paths["cft"]); feed = audit.read_json(paths["feed"])
                old = (NOW - timedelta(days=7)).isoformat()
                if "cft" in old_fields: cft["timestamp"] = old
                if "feed" in old_fields: feed["feed"]["updated"]["$t"] = old
                if "post" in old_fields: feed["feed"]["entry"][0]["published"]["$t"] = old
                raw = {audit.CFT_URL: json.dumps(cft).encode(),
                       audit.CVE_RELEASE_URL: paths["release"].read_bytes(),
                       audit.RELEASE_FEED_URL: json.dumps(feed).encode()}
                with patch.object(audit, "_fetch_metadata", side_effect=lambda url: raw[url]):
                    report = audit.audit_from_official_metadata(source=paths["source"], baseline=paths["baseline"],
                        evidence_dir=root / "captured", now=NOW)
                self.assertEqual(report["status"], "pass")
                self.assertEqual(report["evaluation_status"], "pass")
                self.assertEqual(report["summary"]["missing_release_cves"], [])

    def test_fresh_fetch_does_not_accept_future_content_or_version_mismatch(self):
        for invalid in ("cft", "feed", "post", "version"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); paths = self.fixture(root)
                cft = audit.read_json(paths["cft"]); feed = audit.read_json(paths["feed"])
                future = (NOW + timedelta(minutes=6)).isoformat()
                if invalid == "cft": cft["timestamp"] = future
                if invalid == "feed": feed["feed"]["updated"]["$t"] = future
                if invalid == "post": feed["feed"]["entry"][0]["published"]["$t"] = future
                if invalid == "version":
                    feed["feed"]["entry"][0]["content"]["$t"] = feed["feed"]["entry"][0]["content"]["$t"].replace(FIXED, "155.0.8059.40")
                raw = {audit.CFT_URL: json.dumps(cft).encode(),
                       audit.CVE_RELEASE_URL: paths["release"].read_bytes(),
                       audit.RELEASE_FEED_URL: json.dumps(feed).encode()}
                with patch.object(audit, "_fetch_metadata", side_effect=lambda url: raw[url]), self.assertRaises(ValueError):
                    audit.audit_from_official_metadata(source=paths["source"], baseline=paths["baseline"],
                        evidence_dir=root / "captured", now=NOW)

    def test_fresh_metadata_fetch_cannot_refresh_stale_cve_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); paths = self.fixture(root)
            raw = {audit.CFT_URL: paths["cft"].read_bytes(), audit.CVE_RELEASE_URL: paths["release"].read_bytes(),
                   audit.RELEASE_FEED_URL: paths["feed"].read_bytes()}
            with patch.object(audit, "_fetch_metadata", side_effect=lambda url: raw[url]), self.assertRaisesRegex(ValueError, "stale"):
                audit.audit_from_official_metadata(source=paths["source"], baseline=paths["baseline"],
                    evidence_dir=root / "captured", now=NOW + timedelta(days=2))

    def test_fetch_has_total_deadline_and_rejects_origin_redirect(self):
        import subprocess
        def success(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 35)
            self.assertEqual(command[command.index("--max-time") + 1], "30")
            self.assertNotIn("--location", command)
            Path(command[command.index("--output") + 1]).write_text("{}")
            return subprocess.CompletedProcess(command, 0, "200\n" + audit.CFT_URL, "")
        with patch.object(audit.subprocess, "run", side_effect=success):
            self.assertEqual(audit._fetch_metadata(audit.CFT_URL), b"{}")
        with patch.object(audit.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "302\nhttps://example.com", "")):
            with self.assertRaisesRegex(ValueError, "origin redirect"):
                audit._fetch_metadata(audit.CFT_URL)
        with patch.object(audit.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 35)):
            with self.assertRaisesRegex(ValueError, "bounds"):
                audit._fetch_metadata(audit.CFT_URL)

    def test_html_inline_number_and_version_punctuation_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.fixture(Path(tmp)); feed = audit.read_json(paths["feed"])
            post = feed["feed"]["entry"][0]
            post["content"]["$t"] = f"<p>{FIXED}. This update includes <b>1</b><i>0</i> security fixes. " + " ".join(f"CVE-2026-{1000+i}" for i in range(10)) + "</p>"
            self.assertEqual(len(audit.release_cves(feed, FIXED, NOW)), 10)
            post["content"]["$t"] = post["content"]["$t"].replace(FIXED, FIXED + "0")
            with self.assertRaisesRegex(ValueError, "does not match"): audit.release_cves(feed, FIXED, NOW)

    def test_multiple_platform_boundaries_and_malformed_ranges_are_unknown(self):
        r = record()
        r["containers"]["cna"]["descriptions"][0]["value"] = f"Google Chrome prior to {FIXED} on Windows and 156.0.0.0 on Mac allows execution."
        self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")
        for bad in (None, {}, [None], ["affected"]):
            with self.subTest(bad=bad):
                r = record(); r["containers"]["cna"]["affected"][0]["versions"] = bad
                self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_relevant_non_chrome_cna_and_ambiguous_product_still_blocks(self):
        for description in ("Google Chrome on Mac is vulnerable.", "Chromium has an unspecified vulnerability."):
            r = record(); r["cveMetadata"]["assignerOrgId"] = "other"
            r["containers"]["cna"]["providerMetadata"]["orgId"] = "other"
            r["containers"]["cna"]["affected"][0]["product"] = "n/a"
            r["containers"]["cna"]["descriptions"][0]["value"] = description
            self.assertTrue(audit.relevant(r))
            self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_mentions_do_not_replace_affected_product_identity(self):
        for product in ("Chrome extension", "Firefox", "WordPress Chromium theme"):
            r = record(); r["cveMetadata"]["assignerOrgId"] = "other"
            r["containers"]["cna"]["providerMetadata"]["orgId"] = "other"
            r["containers"]["cna"]["affected"][0]["product"] = product
            self.assertFalse(audit.relevant(r))
        r = record(); r["containers"]["cna"]["affected"][0]["product"] = "FFmpeg"
        self.assertTrue(audit.relevant(r))  # Chrome-CNA component needs review.
        self.assertEqual(audit.evaluate_record(r, FIXED), "unknown")

    def test_other_product_range_does_not_override_chromium_range(self):
        r = record(); r["containers"]["cna"]["affected"].append({"product": "Firefox", "versions": [{"version": "all", "status": "affected"}]})
        self.assertEqual(audit.evaluate_record(r, FIXED), "not_affected")

    def test_unknown_or_contradictory_ranges_never_pass(self):
        for mutation in (lambda c: c["affected"][0]["versions"][0].update(lessThan="156.0.0.0"),
                         lambda c: c["affected"][0]["versions"][0].update(changes=[]),
                         lambda c: c["affected"][0].update(defaultStatus="affected"),
                         lambda c: c.update(descriptions=[])):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                r = record(); mutation(r["containers"]["cna"])
                self.assertEqual(audit.audit(**self.fixture(Path(tmp), records=[r]), now=NOW)["evaluation_status"], "fail")

    def test_missing_cve_from_latest_release_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = audit.audit(**self.fixture(Path(tmp), records=[record("CVE-2026-106359")]), now=NOW)
            self.assertEqual(result["summary"]["missing_release_cves"], ["CVE-2026-106358"])
            self.assertEqual(result["evaluation_status"], "fail")

    def test_bad_artifact_or_manifest_rejected(self):
        for target, key, value in (("source", "platform", "linux64"), ("source", "version", "151.0.7922.77"),
                                   ("cft", "timestamp", "2026-10-01T00:00:00")):
            with self.subTest(target=target, key=key), tempfile.TemporaryDirectory() as tmp:
                paths = self.fixture(Path(tmp)); data = audit.read_json(paths[target]); data[key] = value
                paths[target].write_text(json.dumps(data))
                with self.assertRaises(ValueError): audit.audit(**paths, now=NOW)

    def test_delta_archive_wrong_hash_wrong_origin_and_stale_fail(self):
        for field, value in (("name", "2026-10-09_delta_CVEs_at_1600Z.zip"), ("digest", "sha256:" + "0" * 64),
                             ("browser_download_url", "https://example.com/baseline.zip"), ("size", True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                paths = self.fixture(Path(tmp)); release = audit.read_json(paths["release"])
                release["assets"][0][field] = value; paths["release"].write_text(json.dumps(release))
                with self.assertRaises(ValueError): audit.audit(**paths, now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.fixture(Path(tmp))
            with self.assertRaisesRegex(ValueError, "stale"): audit.audit(**paths, now=NOW + timedelta(days=2))

    def test_incomplete_feed_and_wrong_feed_identity_block(self):
        for key, value in (("id", {"$t": "other"}), ("openSearch$startIndex", {"$t": "2"}), ("entry", [])):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                paths = self.fixture(Path(tmp)); feed = audit.read_json(paths["feed"])
                feed["feed"][key] = value; paths["feed"].write_text(json.dumps(feed))
                with self.assertRaises(ValueError): audit.audit(**paths, now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.fixture(Path(tmp)); text = paths["feed"].read_text().replace("<b>1</b>", "<b>2</b>")
            paths["feed"].write_text(text)
            with self.assertRaisesRegex(ValueError, "incomplete CVE"): audit.audit(**paths, now=NOW)

    def test_duplicate_keys_and_ids_and_unexpected_members_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"): audit.parse_json('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, "invalid JSON"): audit.parse_json('{"a":NaN}')
        for member in ("../../escape.json", "unexpected.txt", "other/CVE-2026-106358.json"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as tmp:
                paths = self.fixture(Path(tmp))
                with zipfile.ZipFile(paths["baseline"], "a") as z: z.writestr(member, json.dumps(record()))
                with self.assertRaises(ValueError): audit.scan_records(paths["baseline"], FIXED)

    def test_sbom_identity_never_aliases_another_ecosystem(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.fixture(Path(tmp)); artifact = audit.bind_artifact(audit.read_json(p["source"]), audit.read_json(p["cft"]), NOW)
            package = {"name": artifact["name"], "versionInfo": artifact["version"], "externalRefs": [
                {"referenceType": "purl", "referenceLocator": artifact["purl"]}], "checksums": [
                {"algorithm": "SHA256", "checksumValue": artifact["archive"]["sha256"]}]}
            audit.bind_sbom(artifact, [package])
            for changed in ([], [package, package], [dict(package, versionInfo="151.0.7922.77")]):
                with self.assertRaises(ValueError): audit.bind_sbom(artifact, changed)
            package["externalRefs"][0]["referenceLocator"] = "pkg:npm/chromium@" + FIXED
            with self.assertRaises(ValueError): audit.bind_sbom(artifact, [package])


if __name__ == "__main__":
    unittest.main()

"""Raw official-query evidence must agree with the admitted ancestor projection.

The fixture contains only synthetic advisory data. No scanner, network or native
compiler executes here. Every negative edit rebinds the outer catalog/review
hashes so semantic validation, rather than a stale digest, must reject it.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_geph_source_owned_advisories import SourceOwnedReviewFixture


class SourceOwnedOSVQueryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.f = SourceOwnedReviewFixture(Path(temporary.name))

    def query(self, index=0):
        return self.f.review["osv_queries"][index]

    def catalog(self, identity):
        return next(e for e in self.f.review["evidence"] if e["id"] == identity)

    def payload(self, identity):
        return (self.f.evidence_root / self.catalog(identity)["path"]).read_bytes()

    def read_json(self, identity):
        return json.loads(self.payload(identity))

    def put(self, identity, payload):
        entry = self.catalog(identity)
        self.f.evidence(identity, entry["path"], payload, entry["kind"])

    def put_json(self, identity, value):
        self.put(identity, json.dumps(value).encode())

    def mutate_receipt(self, mutation):
        identity = self.query()["receipt_evidence"]
        value = self.read_json(identity)
        mutation(value["queries"][0])
        self.put_json(identity, value)

    def replace_response(self, value, *, receipt_ids=None):
        payload = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.put(self.query()["response_evidence"], payload)

        def update(record):
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            if receipt_ids is not None:
                record["advisories"] = receipt_ids

        self.mutate_receipt(update)

    def bind_and_reject(self):
        self.f.save_review()
        with self.assertRaises(ValueError):
            self.f.validate()

    def empty_baseline(self):
        for package in self.f.raw["results"][0]["packages"]:
            package["vulnerabilities"] = []
        for package in self.f.review["packages"]:
            package["inherited_findings"] = []
        self.f.save_raw()
        self.f.save_review()
        self.assertEqual(self.f.validate()["status"], "pass")

    def snapshot(self):
        return copy.deepcopy(self.f.review), {
            e["id"]: self.payload(e["id"]) for e in self.f.review["evidence"]
        }

    def restore(self, snapshot):
        self.f.review = copy.deepcopy(snapshot[0])
        for identity, payload in snapshot[1].items():
            self.put(identity, payload)
        self.f.save_review()

    def use_records_receipt(self):
        """Retain the older real receipt format with one shared projection."""
        receipt_id = self.query()["receipt_evidence"]
        rows, discard = [], set()
        for query in self.f.review["osv_queries"]:
            old = self.read_json(query["receipt_evidence"])["queries"][0]
            rows.append({
                "query": old["request"], "method": old["method"], "url": old["url"],
                "http_status": old["http_status"], "path": old["path"],
                "sha256": old["sha256"], "size_bytes": old["size"],
                "findings": old["advisories"], "started_at_utc": old["requested_at"],
                "completed_at_utc": old["received_at"],
            })
            discard.add(query["request_evidence"])
            if query["receipt_evidence"] != receipt_id:
                discard.add(query["receipt_evidence"])
            query.update(receipt_evidence=receipt_id, request_evidence=None)
        self.f.review["evidence"] = [e for e in self.f.review["evidence"] if e["id"] not in discard]
        projection = self.payload(self.f.review["osv_evidence"])
        self.f.evidence("receipt-projection", "queries/projection.json", projection, "review")
        self.put_json(receipt_id, {
            "schema_version": 1, "scope": "Synthetic retained records-format receipt.",
            "recorded_at_utc": "1999-12-31T12:00:02+00:00", "records": rows,
            "projection": {"path": "projection.json", "size_bytes": len(projection),
                           "sha256": hashlib.sha256(projection).hexdigest()},
        })
        self.f.save_review()

    def test_bound_nonempty_queries_preserve_findings_and_aliases(self):
        self.assertEqual(self.f.review["schema_version"], 2)
        result = self.f.validate()
        self.assertEqual(result["status"], "pass")
        ancestors = [p for p in result["packages"] if p["ancestor"]]
        self.assertEqual(len(ancestors), len(self.f.review["osv_queries"]))
        for package in ancestors:
            self.assertEqual(len(package["inherited_findings"]), 1)
            self.assertEqual(len(package["inherited_findings"][0]["aliases"]), 2)

    def test_empty_raw_queries_require_consistent_empty_projection(self):
        self.empty_baseline()
        self.assertEqual(self.f.validate()["summary"]["unresolved"], 0)

    def test_hidden_raw_advisory_rejected_after_all_outer_hashes_rebound(self):
        self.empty_baseline()
        self.replace_response({"vulns": [{"id": "CVE-TEST-HIDDEN", "aliases": ["GHSA-TEST-HIDDEN"]}]}, receipt_ids=[])
        self.bind_and_reject()

    def test_matching_raw_and_receipt_cannot_hide_advisory_in_projection(self):
        self.empty_baseline()
        self.replace_response({"vulns": [{"id": "CVE-TEST-HIDDEN", "aliases": []}]}, receipt_ids=["CVE-TEST-HIDDEN"])
        self.bind_and_reject()

    def test_empty_raw_cannot_authorize_nonempty_projection(self):
        self.replace_response({}, receipt_ids=[])
        self.bind_and_reject()

    def test_raw_alias_change_cannot_hide_behind_unchanged_advisory_id(self):
        response = self.read_json(self.query()["response_evidence"])
        response["vulns"][0]["aliases"].append("GHSA-TEST-ADDITIONAL")
        self.replace_response(response)
        self.bind_and_reject()

    def test_alias_order_is_not_a_semantic_mismatch(self):
        response = self.read_json(self.query()["response_evidence"])
        response["vulns"][0]["aliases"].reverse()
        self.replace_response(response)
        self.f.save_review()
        self.assertEqual(self.f.validate()["status"], "pass")

    def test_inherited_unknown_or_affected_still_blocks_admission(self):
        saved = self.snapshot()
        for disposition, count in (("unknown", "unresolved"), ("affected", "affected")):
            with self.subTest(disposition=disposition):
                self.restore(saved)
                package = next(p for p in self.f.review["packages"] if p["inherited_findings"])
                package["inherited_findings"][0]["disposition"] = disposition
                self.f.save_review()
                result = self.f.validate()
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["summary"][count], 1)

    def test_query_binding_coordinates_are_exact(self):
        saved = self.snapshot()
        for field, value in (("name", "unexpected-package"), ("version", "99.0.0")):
            with self.subTest(field=field):
                self.restore(saved)
                self.query()[field] = value
                self.bind_and_reject()

    def test_receipt_request_coordinates_are_exact(self):
        saved = self.snapshot()
        changes = (
            lambda r: r["request"]["package"].update(name="unexpected-package"),
            lambda r: r["request"]["package"].update(ecosystem="npm"),
            lambda r: r["request"].update(version="99.0.0"),
        )
        for index, mutation in enumerate(changes):
            with self.subTest(change=index):
                self.restore(saved)
                self.mutate_receipt(mutation)
                self.bind_and_reject()

    def test_request_file_and_receipt_body_must_agree_after_rehash(self):
        identity = self.query()["request_evidence"]
        request = self.read_json(identity)
        request["package"]["name"] = "unexpected-package"
        self.put_json(identity, request)
        digest = hashlib.sha256(self.payload(identity)).hexdigest()
        self.mutate_receipt(lambda r: r.update(request_sha256=digest))
        self.bind_and_reject()

    def test_http_success_method_and_official_url_are_required(self):
        saved = self.snapshot()
        for field, value in (
            ("http_status", 403), ("http_status", "200"),
            ("method", "GET"), ("url", "http://api.osv.dev/v1/query"),
            ("url", "https://api.osv.dev.evil.invalid/v1/query"),
            ("url", "https://api.osv.dev/v1/querybatch"),
        ):
            with self.subTest(field=field, value=value):
                self.restore(saved)
                self.mutate_receipt(lambda r: r.update({field: value}))
                self.bind_and_reject()

    def test_receipt_inner_file_bindings_are_independently_verified(self):
        saved = self.snapshot()
        for field, value in (
            ("path", "../response.json"), ("path", "other-response.json"),
            ("request_path", "../request.json"), ("request_path", "other-request.json"),
            ("sha256", "0" * 64), ("request_sha256", "0" * 64),
            ("size", 0), ("size", "2"),
        ):
            with self.subTest(field=field, value=value):
                self.restore(saved)
                self.mutate_receipt(lambda r: r.update({field: value}))
                self.bind_and_reject()

    def test_raw_errors_pagination_and_malformed_json_are_rejected(self):
        saved = self.snapshot()
        for response in (
            {"error": "upstream unavailable"}, {"errors": ["incomplete"]},
            {"next_page_token": "more", "vulns": []},
            {"vulns": {}}, {"vulns": [None]}, {"vulns": [{"aliases": []}]},
            [], None, b'{"vulns":[],"vulns":[]}', b'{"vulns":NaN}', b'{',
        ):
            with self.subTest(response=response):
                self.restore(saved)
                self.replace_response(response, receipt_ids=[])
                self.bind_and_reject()

    def test_raw_duplicate_findings_or_aliases_are_rejected(self):
        saved = self.snapshot()
        responses = (
            {"vulns": [{"id": "A"}, {"id": "A"}]},
            {"vulns": [{"id": "A", "aliases": ["B", "B"]}]},
            {"vulns": [{"id": "A", "aliases": ["A"]}]},
            {"vulns": [{"id": "A", "aliases": "B"}]},
        )
        for response in responses:
            with self.subTest(response=response):
                self.restore(saved)
                self.replace_response(response, receipt_ids=["A"])
                self.bind_and_reject()

    def test_receipt_advisory_inventory_cannot_omit_or_invent_ids(self):
        saved = self.snapshot()
        for ids in ([], ["CVE-TEST-INVENTED"], ["A", "A"], "A"):
            with self.subTest(ids=ids):
                self.restore(saved)
                self.mutate_receipt(lambda r: r.update(advisories=ids))
                self.bind_and_reject()

    def test_query_coverage_missing_duplicate_swapped_and_downgrade_fail(self):
        saved = self.snapshot()
        mutations = (
            lambda r: r.pop("osv_queries"),
            lambda r: r.update(osv_queries=[]),
            lambda r: r["osv_queries"].pop(),
            lambda r: r["osv_queries"].append(copy.deepcopy(r["osv_queries"][0])),
            lambda r: r["osv_queries"][0].update(response_evidence=r["osv_queries"][1]["response_evidence"]),
            lambda r: r["osv_queries"][0].update(request_evidence=None),
            lambda r: r["osv_queries"][0].update(receipt_evidence="missing-receipt"),
            lambda r: r.update(schema_version=1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(change=index):
                self.restore(saved)
                mutation(self.f.review)
                self.bind_and_reject()

    def test_receipt_missing_or_duplicate_matching_record_is_rejected(self):
        saved = self.snapshot()
        for count in (0, 2):
            with self.subTest(count=count):
                self.restore(saved)
                identity = self.query()["receipt_evidence"]
                receipt = self.read_json(identity)
                receipt["queries"] = receipt["queries"] * count
                self.put_json(identity, receipt)
                self.bind_and_reject()

    def test_records_receipt_preserves_nonempty_findings_without_request_file(self):
        self.use_records_receipt()
        self.assertTrue(all(q["request_evidence"] is None for q in self.f.review["osv_queries"]))
        result = self.f.validate()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(sum(len(p["inherited_findings"]) for p in result["packages"]), 2)

    def test_records_receipt_projection_is_semantic_not_merely_hash_bound(self):
        self.use_records_receipt()
        self.assertEqual(self.f.validate()["status"], "pass")
        projection = self.read_json("receipt-projection")
        projection["results"][0]["packages"][0]["vulnerabilities"] = []
        self.put_json("receipt-projection", projection)
        payload = self.payload("receipt-projection")
        identity = self.query()["receipt_evidence"]
        receipt = self.read_json(identity)
        receipt["projection"].update(sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload))
        self.put_json(identity, receipt)
        self.bind_and_reject()

    def test_records_receipt_rows_bind_status_findings_size_and_raw_hash(self):
        self.use_records_receipt()
        self.assertEqual(self.f.validate()["status"], "pass")
        saved = self.snapshot()
        for field, value in (("http_status", 403), ("findings", []), ("size_bytes", 0), ("sha256", "0" * 64)):
            with self.subTest(field=field):
                self.restore(saved)
                identity = self.query()["receipt_evidence"]
                receipt = self.read_json(identity)
                receipt["records"][0][field] = value
                self.put_json(identity, receipt)
                self.bind_and_reject()

    def test_null_receipt_size_is_not_optional_absence(self):
        saved = self.snapshot()
        for location in ("queries", "records", "projection"):
            with self.subTest(location=location):
                self.restore(saved)
                if location != "queries":
                    self.use_records_receipt()
                identity = self.query()["receipt_evidence"]
                receipt = self.read_json(identity)
                if location == "queries":
                    receipt["queries"][0]["size"] = None
                elif location == "records":
                    receipt["records"][0]["size_bytes"] = None
                else:
                    receipt["projection"]["size_bytes"] = None
                self.put_json(identity, receipt)
                self.bind_and_reject()

    def test_supplemental_registry_query_does_not_escape_receipt_validation(self):
        request = {"package": {"ecosystem": "crates.io", "name": "libsqlite3-sys"}, "version": "0.39.1"}
        request_bytes, response = json.dumps(request).encode(), b"{}"
        self.f.evidence("extra-request", "queries/extra-request.json", request_bytes, "review")
        self.f.evidence("extra-response", "queries/extra-response.json", response, "review")
        identity = self.query()["receipt_evidence"]
        receipt = self.read_json(identity)
        receipt["queries"].append({
            "request": request, "method": "POST", "url": "https://api.osv.dev/v1/query", "http_status": 200,
            "requested_at": "1999-12-31T12:00:00+00:00", "received_at": "1999-12-31T12:00:01+00:00",
            "path": "extra-response.json", "size": len(response), "sha256": hashlib.sha256(response).hexdigest(),
            "advisories": [], "request_path": "extra-request.json", "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        })
        self.put_json(identity, receipt)
        self.f.save_review()
        result = self.f.validate()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["packages"]), 3)
        receipt["queries"][-1]["http_status"] = 403
        self.put_json(identity, receipt)
        self.bind_and_reject()

    def test_clean_schema_one_downgrade_is_not_a_new_review_escape_hatch(self):
        self.f.review["schema_version"] = 1
        self.f.review.pop("osv_queries")
        # Make the shape and ordinary evidence references valid for the old
        # schema. Refusal must come from the immutable historical-policy pin.
        ids = [e["id"] for e in self.f.review["evidence"] if e["id"].startswith("query-")]
        self.f.review["packages"][0]["source_review"]["evidence"].extend(ids)
        self.f.save_review()
        with self.assertRaisesRegex(ValueError, "exact historical policy"):
            self.f.validate()


if __name__ == "__main__":
    unittest.main()

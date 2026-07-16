from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import make_geph_vendor_sbom


REPOSITORY = "aiwaki/slipstream"
SOURCE_COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 1_784_159_400
ROOT_ID = "registry+https://github.com/rust-lang/crates.io-index#geph5-client@0.3.0"


class MakeGephVendorSbomTests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, list[tuple[str, Path]], dict]:
        lock = root / "Cargo.lock"
        lock.write_text(
            '''version = 3

[[package]]
name = "geph5-client"
version = "0.3.0"

[[package]]
name = "common"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "arm-only"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "intel-only"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
''',
            encoding="utf-8",
        )
        common = "registry+https://github.com/rust-lang/crates.io-index#common@1.0.0"
        arm = "registry+https://github.com/rust-lang/crates.io-index#arm-only@2.0.0"
        intel = "registry+https://github.com/rust-lang/crates.io-index#intel-only@3.0.0"

        def metadata(path: Path, extra: str) -> None:
            packages = [
                {"id": ROOT_ID, "name": "geph5-client", "version": "0.3.0", "source": None, "license": "MPL-2.0"},
                {"id": common, "name": "common", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "license": "MIT"},
                {"id": arm, "name": "arm-only", "version": "2.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "license": "MIT"},
                {"id": intel, "name": "intel-only", "version": "3.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "license": "MIT"},
            ]
            path.write_text(
                json.dumps(
                    {
                        "packages": packages,
                        "resolve": {
                            "root": ROOT_ID,
                            "nodes": [
                                {"id": ROOT_ID, "dependencies": [common, extra], "deps": [
                                    {"pkg": common, "dep_kinds": [{"kind": None, "target": None}]},
                                    {"pkg": extra, "dep_kinds": [{"kind": None, "target": None}]},
                                ]},
                                {"id": common, "dependencies": [], "deps": []},
                                {"id": arm, "dependencies": [], "deps": []},
                                {"id": intel, "dependencies": [], "deps": []},
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

        arm_metadata = root / "arm.json"
        intel_metadata = root / "intel.json"
        metadata(arm_metadata, arm)
        metadata(intel_metadata, intel)
        source = {
            "schema_version": 1,
            "crate": {
                "name": "geph5-client",
                "version": "0.3.0",
                "url": "https://static.crates.io/crates/geph5-client/geph5-client-0.3.0.crate",
                "sha256": "d" * 64,
            },
            "features": ["aws_lambda"],
            "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
            "lock_sha256": "e" * 64,
            "release_revision": 1,
        }
        return lock, [
            ("aarch64-apple-darwin", arm_metadata),
            ("x86_64-apple-darwin", intel_metadata),
        ], source

    def test_target_union_is_deduplicated_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock, metadata, source = self._inputs(Path(tmp))
            first = make_geph_vendor_sbom.collect_components(
                cargo_lock=lock,
                cargo_metadata=metadata,
                expected_targets=source["targets"],
            )
            second = make_geph_vendor_sbom.collect_components(
                cargo_lock=lock,
                cargo_metadata=metadata,
                expected_targets=source["targets"],
            )
            self.assertEqual(first, second)
            self.assertEqual({item.name for item in first}, {"common", "arm-only", "intel-only"})

            first_document = make_geph_vendor_sbom.build_spdx_document(
                repository=REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target="macos-universal",
                source=source,
                components=first,
            )
            second_document = make_geph_vendor_sbom.build_spdx_document(
                repository=REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target="macos-universal",
                source=source,
                components=second,
            )
            self.assertEqual(
                json.dumps(first_document, sort_keys=True),
                json.dumps(second_document, sort_keys=True),
            )
            summary = make_geph_vendor_sbom.validate_spdx_document(
                first_document,
                repository=REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target="macos-universal",
                source=source,
            )
            self.assertEqual(summary["dependency_count"], 3)
            root = first_document["packages"][0]
            self.assertEqual(root["checksums"][0]["checksumValue"], "d" * 64)
            self.assertIn("features aws_lambda", root["sourceInfo"])

    def test_metadata_target_order_is_a_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock, metadata, source = self._inputs(Path(tmp))
            with self.assertRaisesRegex(ValueError, "targets"):
                make_geph_vendor_sbom.collect_components(
                    cargo_lock=lock,
                    cargo_metadata=list(reversed(metadata)),
                    expected_targets=source["targets"],
                )

    def test_validation_rejects_source_contract_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock, metadata, source = self._inputs(Path(tmp))
            components = make_geph_vendor_sbom.collect_components(
                cargo_lock=lock,
                cargo_metadata=metadata,
                expected_targets=source["targets"],
            )
            document = make_geph_vendor_sbom.build_spdx_document(
                repository=REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_date_epoch=SOURCE_DATE_EPOCH,
                target="macos-universal",
                source=source,
                components=components,
            )
            tampered = dict(source)
            tampered["crate"] = dict(source["crate"], sha256="f" * 64)
            with self.assertRaisesRegex(ValueError, "sourceInfo"):
                make_geph_vendor_sbom.validate_spdx_document(
                    document,
                    repository=REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    target="macos-universal",
                    source=tampered,
                )


if __name__ == "__main__":
    unittest.main()

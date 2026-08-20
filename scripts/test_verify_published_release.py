from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import make_release_manifest
import verify_published_release


REPOSITORY = "aiwaki/slipstream"
VERSION = "0.1.9-preview.23"
TAG = f"v{VERSION}"
RELEASE_NAME = f"Slipstream {VERSION}"
SOURCE_COMMIT = "a" * 40
TARGET = "aarch64-apple-darwin"
RELEASE_ID = 12345


class VerifyPublishedReleaseTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        state: str = "published",
    ) -> tuple[Path, Path, Path]:
        release_dir = root / "release"
        release_dir.mkdir()
        payloads = {
            "Slipstream-macos-arm64.zip": b"exact zip",
            "latest.json": b'{"version":"0.1.9-preview.23"}\n',
        }
        artifacts = []
        for name, payload in sorted(payloads.items()):
            path = release_dir / name
            path.write_bytes(payload)
            digest, size = make_release_manifest.hash_regular_file(path)
            artifacts.append(
                {
                    "name": name,
                    "kind": "fixture",
                    "media_type": "application/octet-stream",
                    "sha256": digest,
                    "size": size,
                }
            )
        manifest = {
            "schema_version": make_release_manifest.MANIFEST_SCHEMA_VERSION,
            "generator": make_release_manifest.MANIFEST_GENERATOR,
            "product": "Slipstream",
            "repository": REPOSITORY,
            "version": VERSION,
            "tag": TAG,
            "channel": "preview",
            "source": {"commit": SOURCE_COMMIT},
            "build": {"target": TARGET},
            "artifacts": artifacts,
        }
        manifest_path = release_dir / make_release_manifest.MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (release_dir / "release-notes.md").write_text(
            "Exact preview release.\n",
            encoding="utf-8",
        )
        expected_assets = list(artifacts)
        manifest_digest, manifest_size = make_release_manifest.hash_regular_file(
            manifest_path
        )
        expected_assets.append(
            {
                "name": make_release_manifest.MANIFEST_NAME,
                "sha256": manifest_digest,
                "size": manifest_size,
            }
        )
        release_metadata = {
            "id": RELEASE_ID,
            "tag_name": TAG,
            "target_commitish": SOURCE_COMMIT,
            "name": RELEASE_NAME,
            "draft": state == "draft",
            "prerelease": True,
            "published_at": None if state == "draft" else "2026-08-20T12:00:00Z",
            "assets": [
                {
                    "name": asset["name"],
                    "size": asset["size"],
                    "state": "uploaded",
                    "digest": f"sha256:{asset['sha256']}",
                }
                for asset in expected_assets
            ],
        }
        metadata_path = root / "release.json"
        metadata_path.write_text(
            json.dumps(release_metadata),
            encoding="utf-8",
        )
        tag_ref_path = root / "tag.json"
        tag_ref_path.write_text(
            json.dumps(
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {"type": "commit", "sha": SOURCE_COMMIT},
                }
            ),
            encoding="utf-8",
        )
        return release_dir, metadata_path, tag_ref_path

    def _verify(
        self,
        release_dir: Path,
        metadata_path: Path,
        tag_ref_path: Path,
        *,
        state: str = "published",
    ) -> dict[str, object]:
        return verify_published_release.verify_published_release(
            release_metadata_path=metadata_path,
            tag_ref_path=tag_ref_path if state == "published" else None,
            release_dir=release_dir,
            repository=REPOSITORY,
            version=VERSION,
            tag=TAG,
            channel="preview",
            release_name=RELEASE_NAME,
            source_commit=SOURCE_COMMIT,
            target=TARGET,
            release_id=RELEASE_ID,
            state=state,
        )

    def test_accepts_exact_draft_and_published_states(self) -> None:
        for state in ("draft", "published"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                paths = self._fixture(Path(tmp), state=state)

                result = self._verify(*paths, state=state)

                self.assertEqual(result["state"], state)
                self.assertEqual(result["asset_count"], 3)
                self.assertEqual(result["release_id"], RELEASE_ID)

    def test_rejects_tag_pointing_to_another_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._fixture(Path(tmp))
            tag_ref = json.loads(paths[2].read_text(encoding="utf-8"))
            tag_ref["object"]["sha"] = "b" * 40
            paths[2].write_text(json.dumps(tag_ref), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "does not point"):
                self._verify(*paths)

    def test_rejects_wrong_release_identity_or_state(self) -> None:
        cases = (
            ("id", RELEASE_ID + 1, "invalid id"),
            ("name", "Another release", "invalid name"),
            ("draft", True, "invalid draft"),
            ("prerelease", False, "invalid prerelease"),
        )
        for key, value, error in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                paths = self._fixture(Path(tmp))
                metadata = json.loads(paths[1].read_text(encoding="utf-8"))
                metadata[key] = value
                paths[1].write_text(json.dumps(metadata), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, error):
                    self._verify(*paths)

    def test_rejects_draft_with_publication_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._fixture(Path(tmp), state="draft")
            metadata = json.loads(paths[1].read_text(encoding="utf-8"))
            metadata["published_at"] = "2026-08-20T12:00:00Z"
            paths[1].write_text(json.dumps(metadata), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unexpectedly has published_at"):
                self._verify(*paths, state="draft")

    def test_rejects_missing_or_unexpected_remote_asset(self) -> None:
        for mutation, error in (("missing", "missing assets"), ("extra", "unexpected")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                paths = self._fixture(Path(tmp))
                metadata = json.loads(paths[1].read_text(encoding="utf-8"))
                if mutation == "missing":
                    metadata["assets"].pop()
                else:
                    metadata["assets"].append(
                        {
                            "name": "unexpected.bin",
                            "size": 1,
                            "state": "uploaded",
                            "digest": f"sha256:{'0' * 64}",
                        }
                    )
                paths[1].write_text(json.dumps(metadata), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, error):
                    self._verify(*paths)

    def test_rejects_remote_size_or_digest_mismatch(self) -> None:
        for key, value, error in (
            ("size", 999, "size mismatch"),
            ("digest", f"sha256:{'0' * 64}", "digest mismatch"),
        ):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                paths = self._fixture(Path(tmp))
                metadata = json.loads(paths[1].read_text(encoding="utf-8"))
                metadata["assets"][0][key] = value
                paths[1].write_text(json.dumps(metadata), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, error):
                    self._verify(*paths)

    def test_rejects_local_asset_changed_after_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._fixture(Path(tmp))
            (paths[0] / "Slipstream-macos-arm64.zip").write_bytes(b"replacement")

            with self.assertRaisesRegex(ValueError, "differs from manifest"):
                self._verify(*paths)

    def test_rejects_symlinked_api_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._fixture(Path(tmp))
            target = Path(tmp) / "metadata-target.json"
            paths[1].replace(target)
            os.symlink(target, paths[1])

            with self.assertRaisesRegex(ValueError, "cannot open.*safely"):
                self._verify(*paths)

    def test_archival_title_is_idempotent_across_two_passes(self) -> None:
        first = verify_published_release.archival_release_name(
            "Slipstream 0.1.9 (preview 22)"
        )
        self.assertEqual(first, "Slipstream 0.1.9 (preview 22, архивная)")
        second = verify_published_release.archival_release_name(first)
        self.assertEqual(second, first)

        plain_first = verify_published_release.archival_release_name("Slipstream 0.1.9")
        self.assertEqual(plain_first, "Slipstream 0.1.9 (архивная)")
        self.assertEqual(
            verify_published_release.archival_release_name(plain_first),
            plain_first,
        )

    def test_archival_title_rejects_duplicate_or_ambiguous_markers(self) -> None:
        invalid_names = (
            "Slipstream (архивная, архивная)",
            "Slipstream архивная",
            "Slipstream (архивная) extra",
        )
        for name in invalid_names:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "ambiguous archival marker"):
                    verify_published_release.archival_release_name(name)


if __name__ == "__main__":
    unittest.main()

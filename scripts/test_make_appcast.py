from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import make_appcast


class MakeAppcastTests(unittest.TestCase):
    def test_build_appcast_matches_tauri_updater_shape(self) -> None:
        appcast = make_appcast.build_appcast(
            version="0.1.5",
            tag="v0.1.5",
            repository="aiwaki/slipstream",
            signature="sig-value\n",
            pub_date="2026-07-08T12:00:00Z",
        )

        self.assertEqual(appcast["version"], "0.1.5")
        self.assertEqual(appcast["pub_date"], "2026-07-08T12:00:00Z")
        self.assertEqual(
            appcast["platforms"]["darwin-aarch64"]["url"],
            "https://github.com/aiwaki/slipstream/releases/download/"
            "v0.1.5/Slipstream.app.tar.gz",
        )
        self.assertEqual(appcast["platforms"]["darwin-aarch64"]["signature"], "sig-value")

    def test_rejects_tag_that_does_not_match_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be v0.1.5"):
            make_appcast.build_appcast(
                version="0.1.5",
                tag="v0.1.4",
                repository="aiwaki/slipstream",
                signature="sig",
                pub_date="2026-07-08T12:00:00Z",
            )

    def test_accepts_controlled_preview_tag(self) -> None:
        appcast = make_appcast.build_appcast(
            version="0.1.5",
            tag="v0.1.5-preview.42",
            repository="aiwaki/slipstream",
            signature="sig",
            pub_date="2026-07-08T12:00:00Z",
        )

        self.assertEqual(
            appcast["platforms"]["darwin-aarch64"]["url"],
            "https://github.com/aiwaki/slipstream/releases/download/"
            "v0.1.5-preview.42/Slipstream.app.tar.gz",
        )

    def test_rejects_uncontrolled_preview_tag(self) -> None:
        with self.assertRaisesRegex(ValueError, "preview.<run>"):
            make_appcast.build_appcast(
                version="0.1.5",
                tag="v0.1.5-preview.local",
                repository="aiwaki/slipstream",
                signature="sig",
                pub_date="2026-07-08T12:00:00Z",
            )

    def test_rejects_empty_signature(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty updater signature"):
            make_appcast.build_appcast(
                version="0.1.5",
                tag="v0.1.5",
                repository="aiwaki/slipstream",
                signature=" \n",
                pub_date="2026-07-08T12:00:00Z",
            )

    def test_cli_writes_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = root / "Slipstream.app.tar.gz.sig"
            out = root / "latest.json"
            sig.write_text("sig-value\n", encoding="utf-8")

            self.assertEqual(
                make_appcast.main(
                    [
                        "--version",
                        "0.1.5",
                        "--tag",
                        "v0.1.5",
                        "--repository",
                        "aiwaki/slipstream",
                        "--signature-file",
                        str(sig),
                        "--output",
                        str(out),
                        "--pub-date",
                        "2026-07-08T12:00:00Z",
                    ]
                ),
                0,
            )

            appcast = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(appcast["platforms"]["darwin-aarch64"]["signature"], "sig-value")


if __name__ == "__main__":
    unittest.main()

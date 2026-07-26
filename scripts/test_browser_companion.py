import base64
import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPANION = ROOT / "browser-companion" / "chromium"
MANIFEST = COMPANION / "manifest.json"
NATIVE_HOST = ROOT / "app-tauri" / "src-tauri" / "src" / "native_messaging.rs"
EXPECTED_EXTENSION_ID = "cecdingohhpfggapnlbghppcegbaciam"
PRODUCTION_SOURCES = (
    COMPANION / "content.js",
    COMPANION / "detector.js",
    COMPANION / "service-worker-core.js",
    COMPANION / "service-worker.js",
)


def extension_id_from_public_key(encoded_key):
    digest = hashlib.sha256(base64.b64decode(encoded_key)).digest()[:16]
    return "".join(chr(ord("a") + nibble) for byte in digest for nibble in (byte >> 4, byte & 15))


class BrowserCompanionContractTests(unittest.TestCase):
    def test_manifest_has_stable_identity_and_minimal_capabilities(self):
        manifest = json.loads(MANIFEST.read_text())

        self.assertEqual(extension_id_from_public_key(manifest["key"]), EXPECTED_EXTENSION_ID)
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["permissions"], ["nativeMessaging"])
        self.assertNotIn("host_permissions", manifest)
        self.assertNotIn("externally_connectable", manifest)
        self.assertNotIn("web_accessible_resources", manifest)
        self.assertEqual(manifest["content_scripts"][0]["matches"], ["https://*/*"])
        self.assertFalse(manifest["content_scripts"][0]["all_frames"])

    def test_native_host_and_extension_identity_are_exactly_bound(self):
        source = NATIVE_HOST.read_text()

        self.assertIn(f'CHROMIUM_EXTENSION_ID: &str = "{EXPECTED_EXTENSION_ID}"', source)
        self.assertIn(
            f'"chrome-extension://{EXPECTED_EXTENSION_ID}/"',
            source,
        )
        self.assertIn('NATIVE_HOST_NAME: &str = "dev.slipstream.semantic"', source)

    def test_production_detector_contains_no_site_rules(self):
        source = "\n".join(path.read_text() for path in PRODUCTION_SOURCES)
        host_literal = re.compile(
            r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|io|dev|app|co|tv)\b",
            re.IGNORECASE,
        )

        self.assertEqual(host_literal.findall(source), [])
        for forbidden in ("cookie", "localStorage", "sessionStorage", "document.URL"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("innerText", (COMPANION / "content.js").read_text())


if __name__ == "__main__":
    unittest.main()

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import materialize_legacy_update_driver as driver


class LegacyDriverTests(unittest.TestCase):
    def test_digest_mismatch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                driver.materialize(root, b"unreviewed source")
            self.assertEqual(list(root.iterdir()), [])

    def test_preserves_entry_guards_and_refuses_stale_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            examples = root / "app-tauri/src-tauri/examples"
            examples.mkdir(parents=True)
            entry = driver.MODULE + '\nfn guard() { panic!("workstation refused"); }\n'
            (examples / "prepare_packaged_update.rs").write_text(entry)
            source = b"pinned transaction source"
            with patch.object(driver, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
                report = driver.materialize(root, source)
                result = (examples / "prepare_legacy23_update.rs").read_text()
                self.assertEqual(result.replace(
                    '#[path = "legacy23_generated/updater_transaction.rs"]', driver.MODULE), entry)
                self.assertEqual((examples / "legacy23_generated/updater_transaction.rs").read_bytes(), source)
                self.assertIn("not-runtime-qualification", report["coverage"])
                with self.assertRaises(FileExistsError):
                    driver.materialize(root, source)

    def test_changed_module_binding_is_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            examples = root / "app-tauri/src-tauri/examples"
            examples.mkdir(parents=True)
            (examples / "prepare_packaged_update.rs").write_text("mod different;")
            source = b"pinned"
            with patch.object(driver, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
                with self.assertRaisesRegex(ValueError, "module binding"):
                    driver.materialize(root, source)
            self.assertFalse((examples / "legacy23_generated").exists())

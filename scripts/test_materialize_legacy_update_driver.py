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

    def test_real_entry_preserves_guards_but_refuses_new_migration_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            examples = root / "app-tauri/src-tauri/examples"
            examples.mkdir(parents=True)
            actual = Path(__file__).resolve().parents[1] / "app-tauri/src-tauri/examples/prepare_packaged_update.rs"
            (examples / "prepare_packaged_update.rs").write_text(actual.read_text())
            source = b"pinned"
            with patch.object(driver, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
                driver.materialize(root, source)
            generated = (examples / "prepare_legacy23_update.rs").read_text()
            self.assertNotIn("::prepare_legacy_migration_transaction", generated)
            self.assertIn("historical driver cannot prepare an external migration", generated)
            self.assertIn('std::env::var("SLIPSTREAM_DISPOSABLE_CI")', generated)
            self.assertIn("all transaction inputs must be inside RUNNER_TEMP", generated)

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

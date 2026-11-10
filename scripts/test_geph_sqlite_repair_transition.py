"""The reviewed r4 -> r5 SQLite fix is not a generic policy-renewal path."""
import copy
import json
from pathlib import Path
import unittest

import geph_vendor_source as source


class SqliteRepairTransitionTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).parent / "fixtures"
        self.previous = json.loads((root / "geph-rsa-removal-policy-r4.json").read_text())
        self.current = json.loads((root / "geph-sqlite-repair-policy-r5.json").read_text())

    def verify(self, *, binding=None, current=None):
        return source._verify_policy_transition(
            previous_policy=self.previous, current_policy=current or self.current,
            previous_h2_present=False, current_h2_present=False,
            verified_source_binding=binding,
        )

    def test_exact_source_and_review_repair_preserves_registry_rules(self):
        self.assertEqual(self.verify(binding=source.SQLITE_REPAIR_REVIEW_SOURCE_BINDING),
                         "fixed-sqlite-with-reviewed-manifest-only-driver")
        for key in self.previous.keys() - {"source_owned_review"}:
            self.assertEqual(self.previous[key], self.current[key])
        self.assertEqual(self.current["source_owned_review"]["expires"], "2026-12-10")

    def test_policy_only_or_changed_source_lock_fails(self):
        with self.assertRaises(ValueError):
            self.verify()
        for index in range(4):
            binding = list(source.SQLITE_REPAIR_REVIEW_SOURCE_BINDING)
            binding[index] = "0" * 64
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.verify(binding=tuple(binding))

    def test_no_later_expiry_exception_or_scanner_mutation(self):
        for section, key, value in (
            ("source_owned_review", "expires", "2099-12-10"),
            ("source_owned_review", "review_sha256", "0" * 64),
            ("source_owned_review", "source_sha256", "0" * 64),
            ("scanner", "version", "0.0.0"),
        ):
            changed = copy.deepcopy(self.current)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.verify(binding=source.SQLITE_REPAIR_REVIEW_SOURCE_BINDING, current=changed)
        changed = copy.deepcopy(self.current)
        changed["exceptions"][0]["expires"] = "2099-01-01"
        with self.assertRaises(ValueError):
            self.verify(binding=source.SQLITE_REPAIR_REVIEW_SOURCE_BINDING, current=changed)


if __name__ == "__main__":
    unittest.main()

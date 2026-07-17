from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates/slipstream-core"


class SlipstreamCoreBoundaryTests(unittest.TestCase):
    def test_manifest_has_only_platform_neutral_dependencies(self) -> None:
        manifest = (CORE / "Cargo.toml").read_text(encoding="utf-8")

        self.assertIn('name = "slipstream-core"', manifest)
        self.assertIn("publish = false", manifest)
        self.assertIn('serde = { version = "1", features = ["derive"] }', manifest)
        for dependency in ("tauri", "tokio", "libc", "windows", "objc", "swift"):
            self.assertNotRegex(manifest, rf"(?m)^{re.escape(dependency)}(?:\s|-)")

    def test_sources_do_not_own_platform_io(self) -> None:
        forbidden = re.compile(
            r"std::(?:(?:fs|os|process|thread|time)\b|"
            r"\{[^}]*\b(?:fs|os|process|thread|time)\b)|"
            r"(?:Tcp|Udp|Unix)(?:Datagram|Listener|Socket|Stream)|ToSocketAddrs|"
            r"Command::new|unsafe\s*\{"
        )

        sources = sorted((CORE / "src").rglob("*.rs"))
        self.assertGreaterEqual(len(sources), 5)
        self.assertIn(CORE / "src" / "route_policy_activation" / "v1.rs", sources)
        for source in sources:
            text = source.read_text(encoding="utf-8")
            self.assertIsNone(forbidden.search(text), source.relative_to(ROOT))


if __name__ == "__main__":
    unittest.main()

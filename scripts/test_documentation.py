from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    ROOT / "README.md",
    ROOT / "README.en.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "DEVELOPMENT.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "crates" / "slipstream-userspace-stack-evaluation" / "README.md",
    ROOT / "crates" / "slipstream-userspace-stack-effect-evaluation" / "README.md",
    ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
    ROOT / "spike" / "README.md",
    ROOT / "spike" / "VOICEPROBE.md",
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def local_link_target(document: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    target = unquote(target.split("#", 1)[0].split("?", 1)[0])
    return (document.parent / target).resolve()


class DocumentationTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self) -> None:
        missing: list[str] = []
        for document in DOCS:
            text = document.read_text(encoding="utf-8")
            for raw_target in MARKDOWN_LINK.findall(text):
                target = local_link_target(document, raw_target)
                if target is not None and not target.exists():
                    missing.append(f"{document.relative_to(ROOT)} -> {raw_target}")
        self.assertEqual([], missing)

    def test_root_readmes_are_safe_and_current(self) -> None:
        required_links = (
            "DEVELOPMENT.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "docs/ARCHITECTURE.md",
            "docs/README.md",
            "contracts/README.md",
            "docs/ROADMAP.md",
        )
        forbidden = (
            "sudo",
            "tproxy.py --install",
            "Discord voice",
            "голоса Discord",
            "| Windows |",
            "| Android |",
        )
        for name in ("README.md", "README.en.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for link in required_links:
                self.assertIn(link, text, f"{name} must link {link}")
            for phrase in forbidden:
                self.assertNotIn(phrase, text, f"{name} contains {phrase!r}")

    def test_spike_readme_describes_the_daemon(self) -> None:
        text = (ROOT / "spike" / "README.md").read_text(encoding="utf-8")
        self.assertIn("tproxy.py", text)
        self.assertIn("DEVELOPMENT.md", text)
        self.assertNotIn("THROWAWAY", text)
        self.assertNotIn("sudo", text)

    def test_voiceprobe_is_clearly_archived(self) -> None:
        text = (ROOT / "spike" / "VOICEPROBE.md").read_text(encoding="utf-8")
        self.assertIn("Archived research", text)
        self.assertIn("disposable", text)
        self.assertIn("not part of the current runtime", text)

    def test_development_guide_separates_safe_and_privileged_checks(self) -> None:
        text = (ROOT / "DEVELOPMENT.md").read_text(encoding="utf-8")
        self.assertIn("pytest spike scripts -q", text)
        self.assertIn("cargo test", text)
        self.assertIn("SLIPSTREAM_DISPOSABLE_CI=1", text)
        self.assertIn("primary workstation", text)

    def test_build_script_does_not_recommend_installing_the_daemon(self) -> None:
        text = (ROOT / "spike" / "build_daemon.sh").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"sudo\s+.*--install", text))

    def test_public_contribution_surface_preserves_safety_boundaries(self) -> None:
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        issue_template = (
            ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("disposable CI", contributing)
        self.assertIn("primary workstation", contributing)
        self.assertIn("GitHub Security Advisories", security)
        self.assertIn("удаления секретов", issue_template)


if __name__ == "__main__":
    unittest.main()

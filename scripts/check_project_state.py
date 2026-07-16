#!/usr/bin/env python3
"""Validate the compact project-continuity contract used after context resume."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    state = (ROOT / "docs" / "CURRENT_STATE.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    docs_map = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    decisions = (ROOT / "docs" / "DECISIONS.md").read_text(encoding="utf-8")

    required_state_sections = (
        "## Resume Protocol",
        "## Verified Checkpoint",
        "## Next Verified Action",
        "## External Gates",
        "## Update Rule",
    )
    missing = [section for section in required_state_sections if section not in state]

    for milestone in range(5):
        marker = f"| M{milestone} -"
        if marker not in state:
            missing.append(f"milestone row {marker!r}")

    required_references = {
        "AGENTS.md": "docs/CURRENT_STATE.md",
        "docs/README.md": "[CURRENT_STATE.md](CURRENT_STATE.md)",
        "docs/DECISIONS.md": "docs/CURRENT_STATE.md",
    }
    documents = {
        "AGENTS.md": agents,
        "docs/README.md": docs_map,
        "docs/DECISIONS.md": decisions,
    }
    for name, marker in required_references.items():
        if marker not in documents[name]:
            missing.append(f"{name} reference {marker!r}")

    if missing:
        for item in missing:
            print(f"project-state contract missing: {item}")
        return 1

    print("project-state continuity contract: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

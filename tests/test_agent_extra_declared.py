from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_the_agent_extra_adds_guard_agent_in_the_range_the_family_uses() -> None:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r"^agent = \[\s*(.*?)\s*\]$", text, re.MULTILINE | re.DOTALL)

    assert found is not None
    assert found.group(1) == '"guard-agent>=3.2.4",'


def test_the_install_hint_names_the_agent_extra_in_every_page_that_lists_extras() -> (
    None
):
    hint = "tornadoapi-guard[agent]"
    missing = [
        page
        for page in ("README.md", "docs/installation.md")
        if hint not in (_ROOT / page).read_text(encoding="utf-8")
    ]

    assert missing == []

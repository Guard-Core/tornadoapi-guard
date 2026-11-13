from __future__ import annotations

from pathlib import Path

from guard_core.core.checks.factory import DEFAULT_CHECK_CLASSES

_ROOT = Path(__file__).resolve().parent.parent
_PAGES = (
    "docs/api/security-middleware.md",
    "docs/api/security-handler.md",
    "tornadoapi_guard/.agents/skills/tornadoapi-guard/SKILL.md",
    "AGENTS.md",
    "CLAUDE.md",
)


def test_every_page_that_counts_the_checks_counts_the_factorys() -> None:
    count = len(DEFAULT_CHECK_CLASSES)
    wrong = [
        page
        for page in _PAGES
        if f"up to {count} checks" not in (_ROOT / page).read_text(encoding="utf-8")
    ]

    assert wrong == []

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SEPARATOR = "\n___\n"


def _sections(path: Path) -> dict[str, str]:
    # Everything before the first separator is the file's own header.
    chunks = path.read_text(encoding="utf-8").split(_SEPARATOR)[1:]
    return {chunk.strip().splitlines()[0]: chunk.strip() for chunk in chunks}


def test_the_changelog_and_the_release_notes_hold_the_same_version_sections() -> None:
    changelog = _sections(_ROOT / "CHANGELOG.md")
    release_notes = _sections(_ROOT / "docs" / "release-notes.md")

    assert changelog.keys() == release_notes.keys()
    assert [name for name in changelog if changelog[name] != release_notes[name]] == []


def test_no_released_section_is_marked_unreleased() -> None:
    names = _sections(_ROOT / "CHANGELOG.md").keys()

    assert [n for n in names if n != "Unreleased" and "unreleased" in n.lower()] == []

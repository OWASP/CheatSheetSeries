"""Shared pytest fixtures for the scripts/ test suite."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def cheatsheets_dir(tmp_path: Path) -> Path:
    """Return a fresh, empty cheatsheets/ directory inside a temp path.

    Tests that need sample cheatsheet files should write them into this
    directory before invoking the script under test.
    """
    d = tmp_path / "cheatsheets"
    d.mkdir()
    return d


@pytest.fixture
def write_cheatsheet(cheatsheets_dir: Path):
    """Return a callable that writes a cheatsheet file with optional content.

    Usage:
        write_cheatsheet("Foo.md", "# Foo\\n\\n```python\\nprint('x')\\n```")
    """
    def _write(name: str, content: str = "") -> Path:
        path = cheatsheets_dir / name
        path.write_text(content, encoding="utf-8")
        return path
    return _write

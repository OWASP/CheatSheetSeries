"""Tests for scripts/Update_CheatSheets_Index.py."""
from __future__ import annotations

import sys
from collections import OrderedDict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import Update_CheatSheets_Index as idx  # noqa: E402


class TestExtractLanguagesSnippetProvided:
    def test_detects_javascript(self, cheatsheets_dir, write_cheatsheet):
        write_cheatsheet(
            "XSS_Cheat_Sheet.md",
            "# XSS\n\n```javascript\nalert(1);\n```\n",
        )
        assert idx.extract_languages_snippet_provided(
            "XSS_Cheat_Sheet.md", cheatsheets_dir=str(cheatsheets_dir)
        ) == ["Javascript"]

    def test_detects_multiple_languages_in_order_of_marker_list(
        self, cheatsheets_dir, write_cheatsheet
    ):
        # Marker list order is: javascript, java, csharp, c, ...
        # SQL and Python appear later; verify they are returned after
        # the earlier markers in the list.
        write_cheatsheet(
            "Multi.md",
            "```sql\nSELECT 1;\n```\n```python\nprint(1)\n```\n",
        )
        result = idx.extract_languages_snippet_provided(
            "Multi.md", cheatsheets_dir=str(cheatsheets_dir)
        )
        assert result == ["Python", "Sql"]

    def test_returns_empty_list_for_file_without_code_blocks(
        self, cheatsheets_dir, write_cheatsheet
    ):
        write_cheatsheet("Plain.md", "# Just headings\n\nNo code here.\n")
        assert idx.extract_languages_snippet_provided(
            "Plain.md", cheatsheets_dir=str(cheatsheets_dir)
        ) == []

    def test_ignores_unrecognized_languages(
        self, cheatsheets_dir, write_cheatsheet
    ):
        # ``rust`` is not in the marker list — must not be detected.
        write_cheatsheet(
            "Unrecognized.md", "```rust\nfn main() {}\n```\n```python\nprint(1)\n```\n"
        )
        result = idx.extract_languages_snippet_provided(
            "Unrecognized.md", cheatsheets_dir=str(cheatsheets_dir)
        )
        assert "Rust" not in result
        assert "Python" in result

    def test_detection_is_case_and_space_insensitive(
        self, cheatsheets_dir, write_cheatsheet
    ):
        # The implementation lowercases content and strips spaces, so
        # `` ```JavaScript\n `` (no space) is detected the same as
        # `` ```Java Script\n `` (with space). Verify both work.
        write_cheatsheet("A.md", "```JavaScript\nx\n```\n")
        write_cheatsheet("B.md", "```Java Script\nx\n```\n")
        assert idx.extract_languages_snippet_provided(
            "A.md", cheatsheets_dir=str(cheatsheets_dir)
        ) == ["Javascript"]
        assert idx.extract_languages_snippet_provided(
            "B.md", cheatsheets_dir=str(cheatsheets_dir)
        ) == ["Javascript"]


class TestGroupByLetter:
    def test_groups_by_uppercased_first_letter(self):
        result = idx.group_by_letter(["alpha.md", "beta.md", "Alpha2.md"])
        assert "A" in result
        assert "B" in result
        assert result["A"] == ["alpha.md", "Alpha2.md"]
        assert result["B"] == ["beta.md"]

    def test_returns_ordered_dict_sorted_by_letter(self):
        result = idx.group_by_letter(["zebra.md", "apple.md", "mango.md"])
        assert isinstance(result, OrderedDict)
        assert list(result.keys()) == ["A", "M", "Z"]

    def test_preserves_input_order_within_a_letter_group(self):
        files = ["b2.md", "b1.md", "b3.md"]
        result = idx.group_by_letter(files)
        assert result["B"] == files

    def test_empty_input_returns_empty_ordered_dict(self):
        result = idx.group_by_letter([])
        assert list(result.keys()) == []


class TestCleanTrailingWhitespace:
    def test_strips_trailing_whitespace_from_each_line(self, tmp_path):
        f = tmp_path / "with_trailing.md"
        f.write_text("line 1   \nline 2\t\nline 3\n", encoding="utf-8")
        idx.clean_trailing_whitespace(str(f))
        # After rstrip+"\n", trailing whitespace is gone but the
        # newline itself is preserved on every line.
        assert f.read_text(encoding="utf-8") == "line 1\nline 2\nline 3\n"

    def test_handles_file_with_no_trailing_whitespace(self, tmp_path):
        f = tmp_path / "clean.md"
        f.write_text("a\nb\nc\n", encoding="utf-8")
        idx.clean_trailing_whitespace(str(f))
        assert f.read_text(encoding="utf-8") == "a\nb\nc\n"


class TestMain:
    def test_creates_index_file_with_title_and_count(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet("Authentication_Cheat_Sheet.md")
        write_cheatsheet("XSS_Prevention_Cheat_Sheet.md")
        write_cheatsheet("Docker_Security.md")

        output = tmp_path / "Index.md"
        rc = idx.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        assert rc == 0
        content = output.read_text(encoding="utf-8")
        assert content.startswith("# Index Alphabetical\n\n")
        assert "**3** cheat sheets available." in content

    def test_groups_cheatsheets_by_letter_section(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet("Authentication_Cheat_Sheet.md")
        write_cheatsheet("XSS_Prevention_Cheat_Sheet.md")
        write_cheatsheet("Docker_Security.md")

        output = tmp_path / "Index.md"
        idx.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        content = output.read_text(encoding="utf-8")
        assert "## A\n" in content
        assert "## D\n" in content
        assert "## X\n" in content

    def test_includes_language_icons_when_code_blocks_present(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet(
            "XSS_Prevention_Cheat_Sheet.md",
            "# XSS\n\n```javascript\nalert(1);\n```\n",
        )

        output = tmp_path / "Index.md"
        idx.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        content = output.read_text(encoding="utf-8")
        assert "![Javascript](assets/Index_Javascript.svg)" in content

    def test_omits_language_icons_when_no_code_blocks(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet("Plain_Cheat_Sheet.md", "# Plain\n\nNo code.\n")

        output = tmp_path / "Index.md"
        idx.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        content = output.read_text(encoding="utf-8")
        assert "assets/Index_" not in content

    def test_output_has_no_trailing_whitespace(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        # The original script ends with a clean_trailing_whitespace
        # step; verify that step is still executed in main().
        write_cheatsheet("Foo.md", "# Foo\n")

        output = tmp_path / "Index.md"
        idx.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        for line in output.read_text(encoding="utf-8").splitlines():
            assert line == line.rstrip(), f"line has trailing whitespace: {line!r}"

"""Tests for scripts/Generate_CheatSheets_TOC.py."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import Generate_CheatSheets_TOC as toc  # noqa: E402


class TestToDisplayName:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("Authentication_Cheat_Sheet.md", "Authentication"),
            ("XSS_Prevention_Cheat_Sheet.md", "XSS Prevention"),
            ("Docker_Security.md", "Docker Security"),
            ("REST_Security_Cheat_Sheet.md", "REST Security"),
            ("OAuth2_Cheat_Sheet.md", "OAuth2"),
            ("C-Based_Cheat_Sheet.md", "C-Based"),
            # No "Cheat Sheet" suffix
            ("GraphQL.md", "GraphQL"),
            # No underscores, no suffix
            ("README.md", "README"),
        ],
    )
    def test_converts_filename_to_human_readable(self, filename, expected):
        assert toc.to_display_name(filename) == expected

    def test_strips_trailing_whitespace_in_display_name(self):
        # A filename that ends with " Cheat Sheet" should not produce
        # a trailing space in the rendered link.
        assert toc.to_display_name("Foo_Cheat_Sheet.md") == "Foo"

    def test_empty_string_returns_empty(self):
        assert toc.to_display_name("") == ""


class TestShouldSkip:
    @pytest.mark.parametrize(
        "filename",
        [
            "Index.md",
            "IndexASVS.md",
            "IndexMASVS.md",
            "IndexProactiveControls.md",
            "TOC.md",
        ],
    )
    def test_index_and_toc_files_are_skipped(self, filename):
        assert toc.should_skip(filename) is True

    @pytest.mark.parametrize(
        "filename",
        [
            "Authentication_Cheat_Sheet.md",
            "XSS_Prevention_Cheat_Sheet.md",
            "Docker_Security.md",
        ],
    )
    def test_real_cheatsheets_are_not_skipped(self, filename):
        assert toc.should_skip(filename) is False


class TestBuildTocLines:
    def test_returns_four_predefined_index_links(self):
        lines = toc.build_toc_lines([])
        assert len(lines) == 4

    def test_predefined_links_appear_in_known_order(self):
        lines = toc.build_toc_lines([])
        assert "Index.md" in lines[0]
        assert "IndexASVS.md" in lines[1]
        assert "IndexMASVS.md" in lines[2]
        assert "IndexProactiveControls.md" in lines[3]


class TestMain:
    def test_creates_toc_file_with_summary_header(
        self, cheatsheets_dir: Path, tmp_path: Path
    ):
        output = tmp_path / "TOC.md"
        # Script's default relative path is "../cheatsheets" and writes
        # to "TOC.md"; here we call main() with absolute paths so the
        # test does not depend on the caller's cwd.
        rc = toc.main(
            cheatsheets_dir=str(cheatsheets_dir),
            output_file=str(output),
        )
        assert rc == 0
        content = output.read_text(encoding="utf-8")
        assert content.startswith("# Summary\n\n")
        assert "### Cheatsheets" in content

    def test_lists_index_files_only_via_predefined_links(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        # Even when the index files live in the cheatsheets/ directory,
        # the script must not list them a second time as cheatsheets —
        # they appear exactly once, via the pre-defined hardcoded links.
        write_cheatsheet("Index.md", "# Index")
        write_cheatsheet("IndexASVS.md", "# ASVS Index")
        write_cheatsheet("IndexMASVS.md", "# MASVS Index")
        write_cheatsheet("IndexProactiveControls.md", "# PC Index")
        write_cheatsheet("Authentication_Cheat_Sheet.md", "# Auth")

        output = tmp_path / "TOC.md"
        toc.main(cheatsheets_dir=str(cheatsheets_dir), output_file=str(output))
        content = output.read_text(encoding="utf-8")

        # The pre-defined index links are present
        assert "Index Alphabetical" in content
        assert "IndexASVS.md" in content
        # The real cheatsheet is listed under its display name
        assert "[Authentication](cheatsheets/Authentication_Cheat_Sheet.md)" in content
        # Each index file appears exactly once (the pre-defined link),
        # not also as a cheatsheet listing.
        assert content.count("cheatsheets/Index.md)") == 1
        assert content.count("cheatsheets/IndexASVS.md)") == 1
        assert content.count("cheatsheets/IndexMASVS.md)") == 1
        assert content.count("cheatsheets/IndexProactiveControls.md)") == 1
        # The Authentication cheatsheet is not listed under its raw
        # filename — it uses the human-readable display name.
        assert "[Authentication_Cheat_Sheet]" not in content

    def test_sorts_cheatsheets_alphabetically(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet("Z_Cheat_Sheet.md")
        write_cheatsheet("A_Cheat_Sheet.md")
        write_cheatsheet("M_Cheat_Sheet.md")

        output = tmp_path / "TOC.md"
        toc.main(cheatsheets_dir=str(cheatsheets_dir), output_file=str(output))
        content = output.read_text(encoding="utf-8")

        a_pos = content.index("[A]")
        m_pos = content.index("[M]")
        z_pos = content.index("[Z]")
        assert a_pos < m_pos < z_pos

    def test_uses_display_name_with_spaces(
        self, cheatsheets_dir: Path, tmp_path: Path, write_cheatsheet
    ):
        write_cheatsheet("Clickjacking_Defense_Cheat_Sheet.md")

        output = tmp_path / "TOC.md"
        toc.main(cheatsheets_dir=str(cheatsheets_dir), output_file=str(output))
        content = output.read_text(encoding="utf-8")

        assert (
            "[Clickjacking Defense](cheatsheets/Clickjacking_Defense_Cheat_Sheet.md)"
            in content
        )

    def test_empty_cheatsheets_dir_still_writes_predefined_links(
        self, cheatsheets_dir: Path, tmp_path: Path
    ):
        output = tmp_path / "TOC.md"
        toc.main(cheatsheets_dir=str(cheatsheets_dir), output_file=str(output))
        content = output.read_text(encoding="utf-8")
        assert "Index Alphabetical" in content
        assert "Index ASVS" in content
        assert "Index Proactive Controls" in content

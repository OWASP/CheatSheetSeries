#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the summary markdown page that is used
by GitBook to generate the offline website.

The summary markdown page is named "TOC.md" and is generated in the
same location that the script in order to be moved later by the caller script.
"""
import os
import sys
from typing import Iterable, List

# Define templates
cs_md_link_template = "* [%s](cheatsheets/%s)"

# Files that are not actual cheat sheets and must be excluded from the TOC
# even if they happen to live in the cheatsheets/ directory.
_EXCLUDED_FROM_TOC = frozenset({
    "Index.md",
    "IndexASVS.md",
    "IndexMASVS.md",
    "IndexProactiveControls.md",
    "TOC.md",
})


def to_display_name(filename: str) -> str:
    """Convert a cheatsheet filename to its human-readable display name.

    Underscores become spaces, the .md suffix is dropped, and the
    "Cheat Sheet" suffix (if present) is stripped. The result is
    whitespace-stripped so trailing/leading spaces do not leak into
    the rendered link text.

    Examples:
        >>> to_display_name("Authentication_Cheat_Sheet.md")
        'Authentication'
        >>> to_display_name("XSS_Prevention_Cheat_Sheet.md")
        'XSS Prevention'
    """
    return (filename
            .replace("_", " ")
            .replace(".md", "")
            .replace("Cheat Sheet", "")
            .strip())


def should_skip(filename: str) -> bool:
    """Return True for files that should not appear in the generated TOC."""
    return filename in _EXCLUDED_FROM_TOC


def build_toc_lines(cheatsheets: Iterable[str]) -> List[str]:
    """Return the list of fixed pre-defined index links for the TOC.

    These four links are always emitted in this order, regardless of the
    contents of the cheatsheets/ directory.
    """
    return [
        cs_md_link_template % ("Index Alphabetical", "Index.md"),
        cs_md_link_template % ("Index ASVS", "IndexASVS.md"),
        cs_md_link_template % ("Index ASVS", "IndexMASVS.md"),
        cs_md_link_template % ("Index Proactive Controls", "IndexProactiveControls.md"),
    ]


def main(cheatsheets_dir: str = "../cheatsheets", output_file: str = "TOC.md") -> int:
    """Generate the summary markdown page.

    Scans ``cheatsheets_dir`` for files, sorts them alphabetically, and
    writes a SUMMARY-style markdown file at ``output_file``. Returns 0 on
    success.
    """
    cheatsheets = sorted(
        f.name for f in os.scandir(cheatsheets_dir) if f.is_file()
    )
    with open(output_file, "w") as index_file:
        index_file.write("# Summary\n\n")
        index_file.write("### Cheatsheets\n\n")
        for link in build_toc_lines(cheatsheets):
            index_file.write(link)
            index_file.write("\n")
        for cheatsheet in cheatsheets:
            if not should_skip(cheatsheet):
                index_file.write(
                    cs_md_link_template % (to_display_name(cheatsheet), cheatsheet)
                )
                index_file.write("\n")
    print("Summary markdown page generated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

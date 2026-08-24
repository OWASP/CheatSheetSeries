#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the index markdown page that
reference all cheat sheets grouped by the first letter.

The index markdown page is located on the root folder
and is named "Index.md".
"""
import os
import sys
from collections import OrderedDict
from typing import Dict, Iterable, List

# Define utility functions
_LANGUAGE_MARKERS = [
    "javascript", "java", "csharp", "c", "cpp", "html", "xml", "python",
    "ruby", "php", "json", "sql", "bash", "shell", "coldfusion", "perl",
    "vbnet",
]


def extract_languages_snippet_provided(
    cheatsheet: str,
    cheatsheets_dir: str = "../cheatsheets",
) -> List[str]:
    """Detect the languages of code snippets in the given cheatsheet.

    Looks for fenced code blocks (```` ```language ````) whose language
    tag is in the recognized list. The file is read in lowercase and with
    spaces stripped so detection is case- and spacing-insensitive.

    Args:
        cheatsheet: Filename of the cheatsheet within ``cheatsheets_dir``.
        cheatsheets_dir: Directory containing the cheatsheet file.

    Returns:
        A list of recognized language names with their first letter
        capitalized, in the order they were detected.
    """
    languages: List[str] = []
    with open(
        os.path.join(cheatsheets_dir, cheatsheet), encoding="utf8"
    ) as cs_file:
        cs_content = cs_file.read().lower().replace(" ", "")
    for marker in _LANGUAGE_MARKERS:
        if "```" + marker + "\n" in cs_content:
            languages.append(marker.capitalize())
    return languages


def group_by_letter(cheatsheets: Iterable[str]) -> "OrderedDict[str, List[str]]":
    """Group cheatsheet filenames by their first letter (uppercased).

    Filenames are grouped by the uppercase form of their first character.
    The result is an :class:`OrderedDict` sorted by letter, preserving
    the input order of filenames within each letter group.
    """
    index: Dict[str, List[str]] = {}
    for cheatsheet in cheatsheets:
        letter = cheatsheet[0].upper()
        index.setdefault(letter, []).append(cheatsheet)
    return OrderedDict(sorted(index.items()))


def clean_trailing_whitespace(file_path: str) -> None:
    """Strip trailing whitespace from each line in the file (in place)."""
    with open(file_path, "r", encoding="utf-8") as file:
        cleaned_lines = [line.rstrip() + "\n" for line in file]
    with open(file_path, "w", encoding="utf-8") as file:
        file.writelines(cleaned_lines)


# Define templates
cs_md_link_template = "[%s](cheatsheets/%s)"
language_md_link_template = "![%s](assets/Index_%s.svg)"
header_template = "## %s\n\n"
top_menu_template = "[%s](Index.md#%s)"
cs_count_template = "**%s** cheat sheets available."
cs_index_title_template = "# Index Alphabetical\n\n"


def main(
    cheatsheets_dir: str = "../cheatsheets",
    output_file: str = "../Index.md",
) -> int:
    """Regenerate the alphabetical index from the cheatsheets directory.

    Scans ``cheatsheets_dir`` for files, groups them by first letter,
    detects code-snippet languages, and writes the index to
    ``output_file``. Returns 0 on success.
    """
    cheatsheets = [f.name for f in os.scandir(cheatsheets_dir) if f.is_file()]
    index = group_by_letter(cheatsheets)
    cs_count = len(cheatsheets)

    with open(output_file, "w", encoding="utf-8") as index_file:
        index_file.write(cs_index_title_template)
        index_file.write(cs_count_template % cs_count)
        index_file.write(
            "\n\n*Icons beside the cheat sheet name indicate in which "
            "language(s) code snippet(s) are provided.*"
        )
        index_file.write("\n\n")
        # Generate the top menu
        for letter in index:
            index_file.write(top_menu_template % (letter, letter.lower()))
            index_file.write(" ")
        index_file.write("\n\n")
        # Generate letter sections
        index_count = len(index)
        for j, letter in enumerate(index):
            group = index[letter]
            group_count = len(group)
            index_file.write(header_template % letter)
            for i, cs_file in enumerate(group):
                cs_name = cs_file.replace("_", " ").replace(".md", "").strip()
                index_file.write(cs_md_link_template % (cs_name, cs_file))
                languages = extract_languages_snippet_provided(
                    cs_file, cheatsheets_dir=cheatsheets_dir
                )
                if languages:
                    index_file.write(" ")
                    for language in languages:
                        index_file.write(
                            language_md_link_template % (language, language)
                        )
                        index_file.write(" ")
                index_file.write("\n")
                if i + 1 != group_count:
                    index_file.write("\n")
            if j + 1 != index_count:
                index_file.write("\n")

    clean_trailing_whitespace(output_file)
    print("Index updated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate a JSON structure with the list of
all cheatsheets classified by the technology used in the samples
of code provided using the alphabetical index as source:
https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/Index.md

Do not require to have a local copy of the GitHub repository.

Dependencies: pip install requests
"""
import json
import sys
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

import requests

# Define templates
CS_BASE_URL = "https://cheatsheetseries.owasp.org/cheatsheets/%s.html"
INDEX_URL = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/Index.md"
)


def parse_index_line(line: str) -> Optional[Tuple[str, List[str]]]:
    """Parse a single line from ``Index.md``.

    Index lines that reference technology icons have the shape::

        [Cheatsheet Name](cheatsheets/Filename.md) ![Tech](assets/Index_Tech.svg) ...

    This function returns a ``(cheatsheet_name, [technology_names])`` tuple
    for any such line, or ``None`` for lines that do not reference
    technology icons.

    Returns:
        A tuple of the cheatsheet display name and the list of
        uppercased technology names, or ``None`` if the line has no
        technology icon references.
    """
    if "(assets/Index_" not in line:
        return None
    work = line.strip()
    cs_name = work[1:work.index("]")]
    technologies = work.split("!")[1:]
    tech_names = [tech[1:tech.index("]")].upper() for tech in technologies]
    return cs_name, tech_names


def build_technologies_dict(
    index_text: str,
) -> "OrderedDict[str, List[Dict[str, str]]]":
    """Build the technology -> [cheatsheet] mapping from ``Index.md`` text.

    The returned dict preserves the order in which technologies first
    appear in the index, matching the legacy behavior of the script.
    """
    data: "OrderedDict[str, List[Dict[str, str]]]" = OrderedDict()
    for line in index_text.split("\n"):
        parsed = parse_index_line(line)
        if parsed is None:
            continue
        cs_name, tech_names = parsed
        for tech in tech_names:
            data.setdefault(tech, []).append(
                {
                    "CS_NAME": cs_name,
                    "CS_URL": CS_BASE_URL % cs_name.replace(" ", "_"),
                }
            )
    return data


def fetch_index_text(url: str = INDEX_URL) -> Tuple[int, str]:
    """Fetch the ``Index.md`` content from the given URL.

    Returns:
        A ``(status_code, body)`` tuple. Callers are expected to check
        the status code and emit a user-facing error if it is not 200.
    """
    response = requests.get(url)
    return response.status_code, response.text


def main() -> int:
    """Fetch the index and print the technologies JSON to stdout.

    Returns 0 on success and 1 if the upstream index cannot be fetched.
    """
    status, text = fetch_index_text()
    if status != 200:
        print(
            "Cannot load the INDEX content: HTTP %s received!" % status
        )
        return 1
    data = build_technologies_dict(text)
    print(json.dumps(data, sort_keys=True, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

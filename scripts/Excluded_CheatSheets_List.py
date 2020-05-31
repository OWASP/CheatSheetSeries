#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the excluded Cheat sheets page.

The  markdown page is located on the root folder
and is named "Excluded.md".
"""
import os
from collections import OrderedDict

# Define templates
cs_md_link_template = "[%s](https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets_excluded/%s).\n"
header_template = "## %s\n\n"
top_menu_template = "[%s](Excluded.md#%s)"
cs_count_template = "**%s** cheat sheets excluded."
cs_index_title_template = "# Index of Excluded Cheat Sheets\n\n"
cs_index_text_template = "The following Cheat sheets have been removed and are no longer maintained. You can however still find them on the github repositroy.\n\n"
redirect_from_comment_template = "---\n"
redirect_from_command_template = "redirect_from :\n"
redirect_from_item_template = "    -/cheatsheets/%s\n"  

# Scan all CS files
index = {}
cs_count = 0
cheatsheets = [f.name for f in os.scandir("../cheatsheets_excluded") if f.is_file() and f.name.endswith("md") ]
for cheatsheet in cheatsheets:
    letter = cheatsheet[0].upper()
    if letter not in index:
        index[letter] = [cheatsheet]
    else:
        index[letter].append(cheatsheet)
    cs_count += 1
index = OrderedDict(sorted(index.items()))

# Generate the index file
with open("../Excluded.md", "w") as index_file:

    index_file.write(redirect_from_comment_template)
    index_file.write(redirect_from_command_template)
    for letter in index:
        for cs_file in index[letter]:
            cs_name = cs_file.replace(".md", ".html").strip()
            index_file.write(redirect_from_item_template % (cs_name))
    index_file.write(redirect_from_comment_template)

    index_file.write(cs_index_title_template)
    index_file.write(cs_index_text_template)
    index_count = len(index)
    index_file.write(cs_count_template % cs_count)
    index_file.write("\n\n")
    # Generate the top menu
    for letter in index:
        index_file.write(top_menu_template % (letter, letter.lower()))
        index_file.write(" ")
    index_file.write("\n\n")
    # Generate letter sections
    j = 0
    for letter in index:
        cs_count =  len(index[letter])
        index_file.write(header_template % letter)
        i = 0
        for cs_file in index[letter]:
            cs_name = cs_file.replace("_", " ").replace(".md", "").strip()
            index_file.write(cs_md_link_template % (cs_name,cs_file))
            if i != cs_count:
                index_file.write("\n")
        j += 1
        if j != index_count:
            index_file.write("\n")

print("Excluded updated.")
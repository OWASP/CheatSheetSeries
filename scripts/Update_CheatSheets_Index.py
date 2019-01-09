#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the index markdown page that
reference all cheat sheets grouped by the first letter.

The index markdown page is loacted on the root folder 
and is named "Index.md".
"""
import os
from collections import OrderedDict

# Define templates
cs_md_link_template = "[%s](cheatsheets/%s)."
header_template = "# %s (%s cheatsheets)\n\n"
top_menu_template = "[%s](Index.md#%s)"

# Scan all CS files
index = {}
cheatsheets = [f.name for f in os.scandir("../cheatsheets") if f.is_file()]
for cheatsheet in cheatsheets:
    letter = cheatsheet[0].upper()
    if letter not in index:
        index[letter] = [cheatsheet]
    else:
        index[letter].append(cheatsheet)
index = OrderedDict(sorted(index.items()))

# Generate the index file
with open("../Index.md", "w") as index_file:
    # Generate the top menu
    for letter in index:
        index_file.write(top_menu_template % (letter, letter))
        index_file.write(" ")
    index_file.write("\n\n")    
    # Generate letter sections
    index_count = len(index)
    j = 0
    for letter in index:
        cs_count =  len(index[letter])
        index_file.write(header_template % (letter,cs_count))
        i = 0
        for cs_file in index[letter]:
            cs_name = cs_file.replace("_", " ").replace(".md", "").strip()
            index_file.write(cs_md_link_template % (cs_name, cs_file))
            i += 1
            index_file.write("\n")
            if i != cs_count:
                index_file.write("\n")
        j += 1
        if j != index_count:
            index_file.write("\n")

print("Update finished.")
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the summary markdown page that is used
by GitBook to generate the offline website.

The summary markdown page is named "TOC.md" and is generated in the
same location that the script in order to be moved later by the caller script.
"""
import os

# Define templates
cs_md_link_template = "* [%s](cheatsheets/%s)"

# Scan all CS files
cheatsheets = [f.name for f in os.scandir("../cheatsheets") if f.is_file()]
cheatsheets.sort()

# Generate the summary file
with open("TOC.md", "w") as index_file:
    index_file.write("# Summary\n\n")
    index_file.write("### Cheatsheets\n\n")
    index_file.write(cs_md_link_template % ("Index Alphabetical", "Index.md"))
    index_file.write("\n")
    index_file.write(cs_md_link_template % ("Index ASVS", "IndexASVS.md"))
    index_file.write("\n")
    index_file.write(cs_md_link_template % ("Index ASVS", "IndexMASVS.md"))
    index_file.write("\n")
    index_file.write(cs_md_link_template % ("Index Proactive Controls", "IndexProactiveControls.md"))
    index_file.write("\n")
    for cheatsheet in cheatsheets:
        if cheatsheet != "Index.md" and cheatsheet != "IndexASVS.md" and cheatsheet != "IndexMASVS.md" and cheatsheet != "IndexProactiveControls.md" and cheatsheet != "TOC.md":
            cs_name = cheatsheet.replace("_"," ").replace(".md", "").replace("Cheat Sheet", "")
            index_file.write(cs_md_link_template % (cs_name, cheatsheet))
            index_file.write("\n")
print("Summary markdown page generated.")
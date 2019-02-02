#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate the summary markdown page that is used 
by GitBook to generate the offline website.

The summary markdown page is located in the "cheatsheets" folder 
and is named "SUMMARY.md".
"""
import os

# Define templates
cs_md_link_template = "* [%s](%s)"

# Scan all CS files
cheatsheets = [f.name for f in os.scandir("../cheatsheets") if f.is_file()]
cheatsheets.sort()

# Generate the summary file
with open("../cheatsheets/SUMMARY.md", "w") as index_file:
    index_file.write("# Summary\n\n")
    index_file.write("### Cheatsheets\n\n")
    for cheatsheet in cheatsheets:
        if cheatsheet != "SUMMARY.md":
            cs_name = cheatsheet.replace("_"," ").replace(".md", "")
            index_file.write(cs_md_link_template % (cs_name, cheatsheet))
            index_file.write("\n")
print("Summary markdown page generated.")
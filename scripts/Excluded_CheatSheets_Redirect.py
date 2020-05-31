#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to prepend jekyll redirect_from to excluded.html file

"""
import os
from collections import OrderedDict

def prepend(path, text):
    with open(path, 'r+') as f:
        body = f.read()
        f.seek(0)
        f.write(text + body)

redirect_from_comment_template = "---\n"
redirect_from_command_template = "redirect_from :\n"
redirect_from_item_template = "    - \"/cheatsheets/%s\"\n"  

redirect_html_file_path = "../generated/site/excluded.html"

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


prepend(redirect_html_file_path,redirect_from_comment_template)
for letter in index:
    for cs_file in index[letter]:
        cs_name = cs_file.replace(".md", ".html").strip()
        prepend(redirect_html_file_path,redirect_from_item_template % (cs_name))
prepend(redirect_html_file_path,redirect_from_command_template)
prepend(redirect_html_file_path,redirect_from_comment_template)




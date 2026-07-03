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
import sys
import requests
import json
from collections import OrderedDict

# Define templates
CS_BASE_URL = "https://cheatsheetseries.owasp.org/cheatsheets/%s.html"

# Grab the index MD source from the GitHub repository
response = requests.get(
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/Index.md")
if response.status_code != 200:
    print("Cannot load the INDEX content: HTTP %s received!" %
          response.status_code)
    sys.exit(1)
else:
    data = OrderedDict({})
    for line in response.text.split("\n"):
        if "(assets/Index_" in line:
            work = line.strip()
            # Extract the name of the CS
            cs_name = work[1:work.index("]")]
            # Extract technologies and map the CS to them
            technologies = work.split("!")[1:]
            for technology in technologies:
                technology_name = technology[1:technology.index("]")].upper()
                if technology_name not in data:
                    data[technology_name] = []
                data[technology_name].append(
                    {"CS_NAME": cs_name, "CS_URL": CS_BASE_URL % cs_name.replace(" ", "_")})
    # Display the built structure and formatted JSON
    print(json.dumps(data, sort_keys=True, indent=1))
    sys.exit(0)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate an RSS feed XML file based on merged pull requests:

See https://github.com/OWASP/CheatSheetSeries/issues/186

Do not require to have a local copy of the GitHub repository.

Dependencies: pip install requests feedgen
"""
import sys
import requests
import json
from feedgen.feed import FeedGenerator
from datetime import datetime

# Define constants
# API to retrieve the list of PR
# See https://developer.github.com/v3/pulls/#list-pull-requests for explanation
PR_API = "https://api.github.com/repos/OWASP/CheatSheetSeries/pulls?page=1&per_page=10000&state=closed&sort=created&direction=asc"

# Grab the list of open PR
print("[+] Grab the list of closed PR via the GitHub API...")
response = requests.get(PR_API)
if response.status_code != 200:
    print("Cannot load the list of PR content: HTTP %s received!" %
          response.status_code)
    sys.exit(1)
pull_requests = response.json()

# Process the obtained list and generate the feed in memory
print("[+] Process the obtained list and generate the feed in memory (%s items)..." % len(pull_requests))
fg = FeedGenerator()
current_date = datetime.utcnow().strftime("%a, %d %B %Y %H:%M:%S GMT")  # Sun, 19 May 2002 15:21:36 GMT
fg.id("https://cheatsheetseries.owasp.org")
fg.title("OWASP Cheat Sheet Series update")
fg.description("List of the last updates on the content")
fg.author({"name": "Core team", "email": "dominique.righetto@owasp.org"})
fg.link({"href": "https://cheatsheetseries.owasp.org", "rel": "self"})
fg.link({"href": "https://github.com/OWASP/CheatSheetSeries", "rel": "alternate"})
fg.language("en")
fg.pubDate(current_date)
fg.lastBuildDate(current_date)
for pr in pull_requests:
    # Take only merged PR
    if pr["merged_at"] is None:
        continue        
    # Convert merge date from 2019-08-25T06:36:35Z To Sun, 19 May 2002 15:21:36 GMT
    merge_date_src = pr["merged_at"] 
    merge_date_dst = datetime.strptime(merge_date_src, "%Y-%m-%dT%H:%M:%SZ").strftime("%a, %d %B %Y %H:%M:%S GMT")
    fe = fg.add_entry()
    fe.id(pr["html_url"])
    fe.title(pr["title"])
    fe.link({"href": pr["html_url"], "rel": "self"})
    fe.link({"href": pr["url"], "rel": "alternate"})
    fe.pubDate(merge_date_dst)
    fe.updated(merge_date_dst)
    contributors = []
    for assignee in pr["assignees"]:
        contributors.append({"name": assignee["login"], "uri": "https://github.com/%s" % assignee["login"]})
    fe.contributor(contributors)

# Save the feed to a XML file
print("[+] Save the feed to a XML file...")
fg.atom_file("news.xml")
print("[+] Feed saved to 'news.xml'.")
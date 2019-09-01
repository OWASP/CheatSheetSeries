#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to generate an RSS feed XML file based on merged pull requests:
See https://github.com/OWASP/CheatSheetSeries/issues/186
Do not require to have a local copy of the GitHub repository.
Dependencies: pip install requests feedgen
"""
import sys
import json
from datetime import datetime

import requests
from feedgen.feed import FeedGenerator

# Define constants
# API to retrieve the list of PR
# See https://developer.github.com/v3/pulls/#list-pull-requests for explanation
PR_API = "https://api.github.com/repos/OWASP/CheatSheetSeries/pulls?page=1&per_page=1000&state=closed"

# Grab the list of open PR
print("[+] Grab the list of closed PR via the GitHub API...")
response = requests.get(PR_API)
if response.status_code != 200:
    print("Cannot load the list of PR content: HTTP %s received!" %  response.status_code)
    sys.exit(1)
pull_requests = response.json()

# Process the obtained list and generate the feed in memory
print("[+] Process the obtained list and generate the feed in memory (%s) items)..." % len(pull_requests))
feed_generator = FeedGenerator()
current_date = datetime.utcnow().strftime("%a, %d %B %Y %H:%M:%S GMT")  # Sun, 19 May 2002 15:21:36 GMT
feed_generator.id("https://cheatsheetseries.owasp.org/")
feed_generator.title("OWASP Cheat Sheet Series update")
feed_generator.description("List of the last updates on the content")
feed_generator.author({"name": "Core team", "email": "dominique.righetto@owasp.org"})
feed_generator.link({"href": "https://cheatsheetseries.owasp.org", "rel": "self"})
feed_generator.link({"href": "https://github.com/OWASP/CheatSheetSeries", "rel": "alternate"})
feed_generator.language("en")
feed_generator.icon("https://cheatsheetseries.owasp.org/gitbook/images/favicon.ico")
feed_generator.pubDate(current_date)
feed_generator.lastBuildDate(current_date)
for pull_request in pull_requests:
    # Take only merged PR
    if pull_request["merged_at"] is None:
        continue
    # Convert merge date from 2019-08-25T06:36:35Z To Sun, 19 May 2002 15:21:36 GMT
    merge_date_src = pull_request["merged_at"]
    merge_date_dst = datetime.strptime(merge_date_src, "%Y-%m-%dT%H:%M:%SZ").strftime("%a, %d %B %Y %H:%M:%S GMT")
    feed_entry = feed_generator.add_entry()
    feed_entry.id(pull_request["html_url"])
    feed_entry.title(pull_request["title"])
    feed_entry.link({"href": pull_request["html_url"], "rel": "self"})
    feed_entry.link({"href": pull_request["html_url"], "rel": "alternate"})
    feed_entry.pubDate(merge_date_dst)
    feed_entry.updated(merge_date_dst)
    contributors = []
    for assignee in pull_request["assignees"]:
        contributors.append({"name": assignee["login"], "uri": "https://github.com/%s" % assignee['login']})
    feed_entry.contributor(contributors)

# Save the feed to a XML file
print("[+] Save the feed to a XML file...")
feed_generator.atom_file("News.xml")
print("[+] Feed saved to 'News.xml'.")

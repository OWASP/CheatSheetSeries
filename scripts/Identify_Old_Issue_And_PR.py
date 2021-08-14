#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Python3 script to identify any Issue or PR meeting the following criteria:
- For Issue (Comments of the issue do not contain the info when a PR is referenced):
    - Has assignees
    - Has not the label HELP_WANTED or INTERNAL
    - Has not been updated since more than 1 month
- For PR:
    - Has the label WAITING_UPDATE
    - Has not been updated since more than 1 month

Do not require to have a local copy of the GitHub repository.

Dependencies: pip install requests
"""
import sys
import requests
import json
from datetime import datetime

# Define constants
## API to retrieve the list of Issues/PR (GitHub REST API v3 considers every pull request an issue, but not every issue is a pull request)
## Ask to the API to sort the list by the updated date in order to have the oldest on the top on the list
## See https://developer.github.com/v3/issues/#list-issues-for-a-repository for explanation
ISSUE_API = "https://api.github.com/repos/OWASP/CheatSheetSeries/issues?page=1&per_page=1000&sort=updated&direction=asc"
## Expiration delay
MAX_MONTHS_ALLOWED = 1

# Define utility function: Cf criteria in the comment of the script for the criteria
def is_old_issue(issue):
    has_assignees = (len(issue["assignees"]) > 0)
    has_help_wanted_label = False
    has_internal_label = False
    labels = issue["labels"]
    for label in labels:
        if label["name"] == "HELP_WANTED":
            has_help_wanted_label = True
        elif label["name"] == "INTERNAL":
            has_internal_label = True
    return has_assignees and (not has_help_wanted_label and not has_internal_label)

def is_old_pull_request(issue):
    has_waiting_for_update_label = False
    labels = issue["labels"]
    for label in labels:
        if label["name"] == "WAITING_UPDATE":
            has_waiting_for_update_label = True
            break
    return has_waiting_for_update_label

# Grab the list of open Issues/PR
buffer = "Grab the list of open Issues/PR via the GitHub API...\n"
response = requests.get(ISSUE_API)
if response.status_code != 200:
    print("Cannot load the list of Issues/PR content: HTTP %s received!" % response.status_code)
    sys.exit(1)
issues = response.json()

# Process the obtained list
buffer += "Process the obtained list (%s items)...\n" % len(issues)
issues = response.json()
old_issues = {"PR":[], "ISSUE":[]}
for issue in issues:
    # Date format is 2019-08-24T15:29:55Z
    last_update = datetime.strptime(issue["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
    diff_in_months = round(abs((datetime.today() - last_update).days / 30))
    if diff_in_months > MAX_MONTHS_ALLOWED:
        id = str(issue["number"])
        if "pull_request" in issue and is_old_pull_request(issue):
            old_issues["PR"].append(id)
        elif is_old_issue(issue):
            old_issues["ISSUE"].append(id)

# Render the result
if (len(old_issues["PR"]) + len(old_issues["ISSUE"])) != 0:
    buffer += "State:\n"
    if len(old_issues["PR"]) > 0:
        buffer += "Old pull request identified (%s items): %s\n" % (len(old_issues["PR"]), " / ".join(old_issues["PR"]))
    if len(old_issues["ISSUE"]) > 0:
        buffer += "Old issue identified (%s items): %s\n" % (len(old_issues["ISSUE"]), " / ".join(old_issues["ISSUE"]))
else:
    buffer += "State: Nothing identified!"
print(buffer)

# Send notification the project management channel on Slack if the url of the webhook is passed as unique first parameter
if len(sys.argv) == 2:
    if (len(old_issues["PR"]) + len(old_issues["ISSUE"])) == 0:
        color = "good"
    else:
        color = "warning"
    message = "{\"text\": \"Old PR and Issue identification watchdog\",\"attachments\": [ {\"fallback\": \"%s\",\"color\":\"%s\",\"title\": \"Status\",\"text\": \"%s\"}]}" % (color, buffer, buffer)
    request_headers = {"Content-Type": "application/json"}
    response = requests.post(sys.argv[1], headers=request_headers, data=message)
    if response.status_code != 200:
        print("Cannot send notification to slack: HTTP %s received!" % response.status_code)
        sys.exit(2)
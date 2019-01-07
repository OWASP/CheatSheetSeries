#!/bin/bash
# Script in charge of auditing the released cheatsheets MD files
# in order to detect dead links
cd ../cheatsheets
find . -name \*.md -exec markdown-link-check -c ../.markdownlinkcheck.json {} \; 1>../link-check-result.out 2>&1
errors=`grep -c "ERROR:" ../link-check-result.out`
content=`cat ../link-check-result.out`
if [[ $errors != "0" ]]
then
    echo "[!] Error(s) found by the Links validator: $errors CS have dead links !"
    exit $errors
else
    echo "[+] No error found by the Links validator."
fi
#!/bin/bash
# Script in charge of auditing the released cheatsheets MD files
# with the linter policy defined at project level
cd ..
markdownlint -o linter-result.out cheatsheets
errors=`wc -m linter-result.out | cut -d' ' -f1`
content=`cat linter-result.out`
if [[ $errors != "0" ]]
then
    echo "[!] Error(s) found by the Linter: $content"
    exit $errors
else
    echo "[+] No error found by the Linter."
fi
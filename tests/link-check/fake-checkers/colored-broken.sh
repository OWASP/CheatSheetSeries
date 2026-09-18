#!/usr/bin/env bash
# Simulate colored markdown-link-check output for a dead link.
file="${!#}"
printf '\033[33mFILE: %s\033[0m\n' "$file"
printf '  \033[31m[✖] https://example.invalid/missing\033[0m\n'
echo "  ERROR: 1 dead link found!" >&2
exit 1

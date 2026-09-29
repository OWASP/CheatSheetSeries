#!/bin/bash
# Compatibility wrapper for auditing the released cheat sheet Markdown files.

set -eu

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec node "$script_dir/Check_Markdown_Links.js"

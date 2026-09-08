#!/bin/bash
# Script in charge of auditing the released cheatsheets MD files
# in order to detect dead links

set -u

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
checker="${MARKDOWN_LINK_CHECK_BIN:-$repo_root/node_modules/.bin/markdown-link-check}"
config="${MARKDOWN_LINK_CHECK_CONFIG:-$repo_root/markdown-link-check-config.json}"
target_dir="${MARKDOWN_LINK_CHECK_TARGET:-$repo_root/cheatsheets}"
log_file="${MARKDOWN_LINK_CHECK_LOG:-$repo_root/log}"

report_failure() {
    printf '%s\n' "$1" >&2
    printf '%s\n' "$1" >> "$log_file"
}

if ! : > "$log_file"; then
    printf '[!] Cannot write link-check log: %s\n' "$log_file" >&2
    exit 1
fi

if [[ ! -x "$checker" ]]; then
    report_failure "[!] Link checker executable is unavailable: $checker"
    exit 127
fi

if [[ ! -f "$config" ]]; then
    report_failure "[!] Link checker configuration is unavailable: $config"
    exit 1
fi

if [[ ! -d "$target_dir" ]]; then
    report_failure "[!] Link-check target directory is unavailable: $target_dir"
    exit 1
fi

file_list="$(mktemp "${TMPDIR:-/tmp}/markdown-link-check.XXXXXX")" || {
    report_failure "[!] Cannot create the link-check file list."
    exit 1
}
trap 'rm -f "$file_list"' EXIT

if ! find "$target_dir" -type f -name '*.md' -print0 > "$file_list"; then
    report_failure "[!] Cannot enumerate Markdown files under: $target_dir"
    exit 1
fi

failures=0
while IFS= read -r -d '' markdown_file; do
    if ! "$checker" -c "$config" "$markdown_file" >> "$log_file" 2>&1; then
        failures=$((failures + 1))
    fi
done < "$file_list"

if (( failures > 0 )); then
    printf '[!] Link validator failed for %d Markdown file(s).\n' "$failures" >&2
    exit 1
fi

printf '[+] No error found by the link validator.\n'

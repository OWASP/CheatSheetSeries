#!/usr/bin/env bash
# Fail-closed Markdown link checker for the Cheat Sheet Series.
#
# Writes checker output to ./log and ./err in the repository root so
# .github/workflows/md-link-check.yml can extract broken-link details.
# Never prints "All good" unless every targeted file was actually checked
# and the checker reported no errors.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

CONFIG="${MARKDOWN_LINK_CHECK_CONFIG:-$ROOT/markdown-link-check-config.json}"
CHECKER="${MARKDOWN_LINK_CHECK:-$ROOT/node_modules/.bin/markdown-link-check}"
LOG="$ROOT/log"
ERR="$ROOT/err"

fail_tooling() {
  echo "$1" >&2
  exit 1
}

if [[ ! -x "$CHECKER" ]]; then
  fail_tooling "markdown-link-check is not available at $CHECKER
Install dependencies with: npm ci --ignore-scripts"
fi

if [[ ! -f "$CONFIG" ]]; then
  fail_tooling "Link-check config not found: $CONFIG"
fi

if [[ "$#" -eq 0 ]]; then
  set -- cheatsheets
fi

for target in "$@"; do
  if [[ ! -e "$target" ]]; then
    fail_tooling "No such file or directory: $target"
  fi
done

files=()
while IFS= read -r path; do
  [[ -n "$path" ]] && files+=("$path")
done < <(
  for target in "$@"; do
    if [[ -d "$target" ]]; then
      find "$target" -type f -name '*.md' -print
    else
      printf '%s\n' "$target"
    fi
  done | LC_ALL=C sort
)

if [[ "${#files[@]}" -eq 0 ]]; then
  fail_tooling "No Markdown files found to check."
fi

: >"$LOG"
: >"$ERR"

tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "$tmp_out" "$tmp_err"' EXIT

invocation_failed=0
for file in "${files[@]}"; do
  if FORCE_COLOR=0 NO_COLOR=1 "$CHECKER" -c "$CONFIG" "$file" >"$tmp_out" 2>"$tmp_err"; then
    file_status=0
  else
    file_status=$?
  fi

  # Keep stdout and stderr together in log so the workflow can extract FILE:
  # and [✖] lines. markdown-link-check 3.x prints ERROR: on stderr.
  {
    cat "$tmp_out"
    cat "$tmp_err"
  } | tee -a "$LOG"
  cat "$tmp_err" | tee -a "$ERR" >&2

  if [[ "$file_status" -ne 0 ]]; then
    invocation_failed=1
  fi
done

if grep -q "ERROR:" "$LOG" "$ERR"; then
  exit 113
fi

if [[ "$invocation_failed" -ne 0 ]]; then
  echo "markdown-link-check failed for one or more files." >&2
  exit 1
fi

echo "All good"
exit 0

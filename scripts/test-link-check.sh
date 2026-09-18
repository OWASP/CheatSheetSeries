#!/usr/bin/env bash
# Regression tests for fail-closed Markdown link checking (issue #2407).
# Uses local fixtures only; does not scan the live cheatsheets corpus.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCRIPT="$ROOT/scripts/Apply_Link_Check.sh"
FIXTURES="$ROOT/tests/link-check/fixtures"
FAKE_CHECKERS="$ROOT/tests/link-check/fake-checkers"
failures=0

run_case() {
  local name="$1"
  local expected_status="$2"
  local expect_all_good="$3"
  shift 3

  local out
  local status
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e

  if [[ "$expected_status" -eq 0 ]]; then
    if [[ "$status" -ne 0 ]]; then
      echo "FAIL: $name (expected exit 0, got $status)"
      printf '%s\n' "$out"
      failures=$((failures + 1))
      return
    fi
  else
    if [[ "$status" -eq 0 ]]; then
      echo "FAIL: $name (expected non-zero exit, got 0)"
      printf '%s\n' "$out"
      failures=$((failures + 1))
      return
    fi
  fi

  if [[ "$expect_all_good" -eq 1 ]]; then
    if ! grep -q "All good" <<<"$out"; then
      echo "FAIL: $name (expected 'All good' on success)"
      printf '%s\n' "$out"
      failures=$((failures + 1))
      return
    fi
  else
    if grep -q "All good" <<<"$out"; then
      echo "FAIL: $name (printed 'All good' on failure)"
      printf '%s\n' "$out"
      failures=$((failures + 1))
      return
    fi
  fi

  echo "PASS: $name"
}

run_case "valid fixture exits zero" 0 1 \
  bash "$SCRIPT" "$FIXTURES/valid"

run_case "broken-link fixture exits non-zero" 1 0 \
  bash "$SCRIPT" "$FIXTURES/broken"

run_case "missing checker exits non-zero" 1 0 \
  env MARKDOWN_LINK_CHECK="$FAKE_CHECKERS/missing-checker" \
  bash "$SCRIPT" "$FIXTURES/valid"

run_case "crashing checker exits non-zero" 1 0 \
  env MARKDOWN_LINK_CHECK="$FAKE_CHECKERS/crash.sh" \
  bash "$SCRIPT" "$FIXTURES/valid"

run_case "silent checker exits non-zero" 1 0 \
  env MARKDOWN_LINK_CHECK="$FAKE_CHECKERS/silent.sh" \
  bash "$SCRIPT" "$FIXTURES/valid"

run_case "ANSI-colored broken output exits non-zero" 1 0 \
  env MARKDOWN_LINK_CHECK="$FAKE_CHECKERS/colored-broken.sh" \
  bash "$SCRIPT" "$FIXTURES/valid"

set +e
env MARKDOWN_LINK_CHECK="$FAKE_CHECKERS/colored-broken.sh" \
  bash "$SCRIPT" "$FIXTURES/valid" >/dev/null 2>&1
set -e
if grep -qE '^FILE:' "$ROOT/log" && grep -qE '\[✖\]' "$ROOT/log"; then
  echo "PASS: ANSI-colored broken-link details written to log"
else
  echo "FAIL: log is missing a leading FILE: or [✖] line after ANSI stripping"
  failures=$((failures + 1))
fi

if [[ "$failures" -ne 0 ]]; then
  echo "$failures link-check regression test(s) failed."
  exit 1
fi

echo "All link-check regression tests passed."
exit 0

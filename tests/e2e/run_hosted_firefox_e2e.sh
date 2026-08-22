#!/usr/bin/env bash
# Exercise an isolated Firefox profile while the real browser owns cookies.sqlite.
set -euo pipefail

profile="${ROOKIE_E2E_FIREFOX_PROFILE:?ROOKIE_E2E_FIREFOX_PROFILE must be set}"
mkdir -p "$profile"
args=(
  tests/e2e/run_exact_corpus_e2e.py
  --engine firefox
  --profile "$profile"
  --browser-id "${ROOKIE_E2E_BROWSER_ID:-firefox}"
)
if command -v xvfb-run >/dev/null 2>&1; then
  args+=(--xvfb)
fi
.venv/bin/python "${args[@]}"

active_args=(
  tests/e2e/run_active_writer_e2e.py
  --engine firefox
  --profile "${profile}-active-writer"
  --browser-id "${ROOKIE_E2E_BROWSER_ID:-firefox}"
)
if command -v xvfb-run >/dev/null 2>&1; then
  active_args+=(--xvfb)
fi
.venv/bin/python "${active_args[@]}"

.venv/bin/python tests/e2e/browser_coverage_contract.py core_firefox \
  --capability exact_set --capability active_writer --capability detailed \
  --surface rust --surface python --surface node --surface cli

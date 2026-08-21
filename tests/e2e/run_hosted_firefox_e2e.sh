#!/usr/bin/env bash
# Exercise an isolated Firefox profile while the real browser owns cookies.sqlite.
set -euo pipefail

profile="${ROOKIE_E2E_FIREFOX_PROFILE:?ROOKIE_E2E_FIREFOX_PROFILE must be set}"
mkdir -p "$profile"
args=(
  tests/e2e/run_active_writer_e2e.py
  --engine firefox
  --profile "$profile"
)
if command -v xvfb-run >/dev/null 2>&1; then
  args+=(--xvfb)
fi
.venv/bin/python "${args[@]}"

#!/usr/bin/env bash
# Seed a Chromium-family browser and assert rust/python/node/cli on Unix.
set -euo pipefail

channel="${1:?usage: run_hosted_chromium_e2e.sh <channel>}"
user_data="${ROOKIE_E2E_USER_DATA_DIR:?ROOKIE_E2E_USER_DATA_DIR must be set}"
mkdir -p "$user_data"

run_inner() {
  python3 tests/e2e/cookie_server.py &
  SERVER_PID=$!
  cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    if [[ -n "${ROOKIE_E2E_KEYCHAIN_SERVICE:-}" ]]; then
      /usr/bin/security delete-generic-password \
        -a "${ROOKIE_E2E_KEYCHAIN_ACCOUNT:-Chrome}" \
        -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT

  if [[ -n "${ROOKIE_E2E_KEYCHAIN_SERVICE:-}" ]]; then
    account="${ROOKIE_E2E_KEYCHAIN_ACCOUNT:-Chrome}"
    /usr/bin/security delete-generic-password \
      -a "$account" -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" >/dev/null 2>&1 || true
    /usr/bin/security add-generic-password -U \
      -a "$account" -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" -w mock_password
  fi

  ready=0
  for _ in $(seq 1 30); do
    if curl -fs http://127.0.0.1:8765/ >/dev/null; then
      ready=1
      break
    fi
    sleep 0.5
  done
  test "$ready" = 1

  if command -v xvfb-run >/dev/null 2>&1; then
    xvfb-run -a node tests/e2e/seed_chromium_cookie.mjs \
      "$channel" "$user_data" "http://127.0.0.1:8765/set"
  else
    node tests/e2e/seed_chromium_cookie.mjs \
      "$channel" "$user_data" "http://127.0.0.1:8765/set"
  fi

  test -f "$user_data/Default/Network/Cookies" || test -f "$user_data/Default/Cookies"
  cargo test --test e2e_chrome --locked -- --ignored --nocapture
  .venv/bin/python tests/e2e/assert_chrome_cookie.py
  node tests/e2e/assert_chrome_cookie.mjs
  cookies_db="$user_data/Default/Network/Cookies"
  [[ -f "$cookies_db" ]] || cookies_db="$user_data/Default/Cookies"
  .venv/bin/python tests/e2e/assert_cli_cookie.py "$cookies_db"
}

export channel user_data
if [[ "$(uname -s)" == "Linux" ]]; then
  dbus-run-session -- bash -euo pipefail -c '
    eval "$(printf "\n" | gnome-keyring-daemon --unlock || true)"
    eval "$(gnome-keyring-daemon --start --components=secrets || true)"
    export XDG_CURRENT_DESKTOP=GNOME
    '"$(declare -f run_inner)"'
    run_inner
  '
else
  run_inner
fi

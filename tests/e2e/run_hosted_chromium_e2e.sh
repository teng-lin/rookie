#!/usr/bin/env bash
# Exercise an isolated Chromium profile while the real browser owns its DB.
set -euo pipefail

channel="${1:?usage: run_hosted_chromium_e2e.sh <channel>}"
user_data="${ROOKIE_E2E_USER_DATA_DIR:?ROOKIE_E2E_USER_DATA_DIR must be set}"
browser_id="${ROOKIE_E2E_BROWSER_ID:-chrome}"
mkdir -p "$user_data"

run_inner() {
  cleanup() {
    if [[ -n "${ROOKIE_E2E_KEYCHAIN_SERVICE:-}" ]]; then
      cleanup_accounts=("${ROOKIE_E2E_KEYCHAIN_ACCOUNT:-Chrome}")
      if [[ "$ROOKIE_E2E_KEYCHAIN_SERVICE" == "Chrome Safe Storage" ]]; then
        cleanup_accounts+=("Chrome" "Chromium")
      fi
      cleanup_seen=""
      for cleanup_account in "${cleanup_accounts[@]}"; do
        case " $cleanup_seen " in
          *" $cleanup_account "*) continue ;;
        esac
        cleanup_seen+=" $cleanup_account"
        /usr/bin/security delete-generic-password \
          -a "$cleanup_account" \
          -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" >/dev/null 2>&1 || true
      done
    fi
  }
  trap cleanup EXIT

  if [[ -n "${ROOKIE_E2E_KEYCHAIN_SERVICE:-}" ]]; then
    account="${ROOKIE_E2E_KEYCHAIN_ACCOUNT:-Chrome}"
    accounts=("$account")
    if [[ "$ROOKIE_E2E_KEYCHAIN_SERVICE" == "Chrome Safe Storage" ]]; then
      accounts+=("Chrome" "Chromium")
    fi
    seen=""
    for account in "${accounts[@]}"; do
      case " $seen " in
        *" $account "*) continue ;;
      esac
      seen+=" $account"
      /usr/bin/security delete-generic-password \
        -a "$account" -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" >/dev/null 2>&1 || true
      /usr/bin/security add-generic-password -U \
        -a "$account" -s "$ROOKIE_E2E_KEYCHAIN_SERVICE" -w mock_password
    done
  fi

  args=(
    tests/e2e/run_active_writer_e2e.py
    --engine chromium
    --profile "$user_data"
    --channel "$channel"
    --browser-id "$browser_id"
  )
  if command -v xvfb-run >/dev/null 2>&1; then
    args+=(--xvfb)
  fi
  .venv/bin/python "${args[@]}"
}

export channel user_data browser_id
export ROOKIE_E2E_KEYCHAIN_SERVICE="${ROOKIE_E2E_KEYCHAIN_SERVICE:-}"
export ROOKIE_E2E_KEYCHAIN_ACCOUNT="${ROOKIE_E2E_KEYCHAIN_ACCOUNT:-}"
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

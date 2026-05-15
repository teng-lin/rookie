#!/usr/bin/env bash
# Run the rookie CLI against an explicit cookies path and assert that the
# seeded `rookie_ci=bar` cookie is in the JSON output.
#
# Usage:
#   assert_cli_cookie.sh <cookies-path> [key-path] [domain]
#
# Examples:
#   # Firefox / unencrypted SQLite: pass just the db
#   assert_cli_cookie.sh "$ROOKIE_E2E_FIREFOX_PROFILE/cookies.sqlite"
#
#   # Linux Chrome / libsecret: --path is enough, no key file needed
#   assert_cli_cookie.sh "$user_data_dir/Default/Network/Cookies"
#
#   # Windows Chrome: pass both Cookies and Local State paths
#   assert_cli_cookie.sh "$user_data_dir/Default/Network/Cookies" "$user_data_dir/Local State"

set -euo pipefail

COOKIES_PATH="${1:?cookies path required}"
KEY_PATH="${2:-}"
DOMAIN="${3:-${ROOKIE_E2E_DOMAIN:-127.0.0.1}}"

if [ ! -f "$COOKIES_PATH" ]; then
  echo "no cookies db at $COOKIES_PATH" >&2
  exit 1
fi

CLI_ARGS=("--path" "$COOKIES_PATH" "--domains" "$DOMAIN" "--format" "json")
if [ -n "$KEY_PATH" ]; then
  CLI_ARGS+=("--key-path" "$KEY_PATH")
fi

# Suppress rookie's `log::info!` lines — they go through tracing-subscriber
# which (with RUST_LOG unset) writes INFO to the same place as the JSON
# output, polluting jq's input. RUST_LOG=error silences everything below
# error level. stderr is dropped for the same reason.
OUT=$(RUST_LOG=error ./target/release/rookie "${CLI_ARGS[@]}" 2>/dev/null)

if ! echo "$OUT" | jq -e '.[] | select(.name == "rookie_ci" and .value == "bar")' >/dev/null; then
  echo "CLI did not return rookie_ci=bar; output was:" >&2
  echo "$OUT" >&2
  exit 1
fi

COUNT=$(echo "$OUT" | jq 'length')
echo "rookie CLI: rookie_ci=bar verified ($COUNT cookies for $DOMAIN)"

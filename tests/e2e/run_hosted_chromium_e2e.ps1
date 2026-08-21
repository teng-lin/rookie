# Exercise an isolated Chromium profile while the real browser owns its DB.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

if ($args.Count -lt 1) {
    throw "usage: run_hosted_chromium_e2e.ps1 <channel>"
}
$channel = $args[0]
$userData = $env:ROOKIE_E2E_USER_DATA_DIR
if (-not $userData) { throw "ROOKIE_E2E_USER_DATA_DIR must be set" }
$browserId = if ($env:ROOKIE_E2E_BROWSER_ID) { $env:ROOKIE_E2E_BROWSER_ID } else { "chrome" }
New-Item -ItemType Directory -Force -Path $userData | Out-Null

& .\.venv\Scripts\python.exe tests/e2e/run_active_writer_e2e.py `
    --engine chromium `
    --profile $userData `
    --channel $channel `
    --browser-id $browserId
if ($LASTEXITCODE -ne 0) { throw "Chromium active-writer E2E failed" }

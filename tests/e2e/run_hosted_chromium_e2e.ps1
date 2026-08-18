# Seed a Chromium-family browser and assert rust/python/node/cli on Windows.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

if ($args.Count -lt 1) {
    throw "usage: run_hosted_chromium_e2e.ps1 <channel>"
}
$channel = $args[0]
$userData = $env:ROOKIE_E2E_USER_DATA_DIR
if (-not $userData) { throw "ROOKIE_E2E_USER_DATA_DIR must be set" }
New-Item -ItemType Directory -Force -Path $userData | Out-Null

$server = Start-Process python -ArgumentList "tests/e2e/cookie_server.py" -PassThru
try {
    $serverReady = $false
    for ($i = 1; $i -le 30; $i++) {
        try {
            Invoke-WebRequest -Uri http://127.0.0.1:8765/ -UseBasicParsing | Out-Null
            $serverReady = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $serverReady) { throw "cookie server did not become ready" }

    node tests/e2e/seed_chromium_cookie.mjs $channel $userData "http://127.0.0.1:8765/set"

    $cookiesDb = Join-Path $userData "Default\Network\Cookies"
    if (-not (Test-Path $cookiesDb)) {
        $cookiesDb = Join-Path $userData "Default\Cookies"
    }
    if (-not (Test-Path $cookiesDb)) { throw "missing Cookies database" }
    $localState = Join-Path $userData "Local State"

    cargo test --test e2e_chrome --locked -- --ignored --nocapture
    & .\.venv\Scripts\python.exe tests/e2e/assert_chrome_cookie.py
    node tests/e2e/assert_chrome_cookie.mjs
    & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py `
        $cookiesDb --key-path $localState
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}

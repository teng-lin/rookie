# Exercise an isolated Firefox profile while the real browser owns cookies.sqlite.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$profile = $env:ROOKIE_E2E_FIREFOX_PROFILE
if (-not $profile) { throw "ROOKIE_E2E_FIREFOX_PROFILE must be set" }
New-Item -ItemType Directory -Force -Path $profile | Out-Null

& .\.venv\Scripts\python.exe tests/e2e/run_active_writer_e2e.py `
    --engine firefox `
    --profile $profile
if ($LASTEXITCODE -ne 0) { throw "Firefox active-writer E2E failed" }

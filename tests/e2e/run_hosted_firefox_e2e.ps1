# Exercise an isolated Firefox profile while the real browser owns cookies.sqlite.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$firefoxProfile = $env:ROOKIE_E2E_FIREFOX_PROFILE
if (-not $firefoxProfile) { throw "ROOKIE_E2E_FIREFOX_PROFILE must be set" }
New-Item -ItemType Directory -Force -Path $firefoxProfile | Out-Null

& .\.venv\Scripts\python.exe tests/e2e/run_exact_corpus_e2e.py `
    --engine firefox `
    --profile $firefoxProfile `
    --browser-id "firefox"
if ($LASTEXITCODE -ne 0) { throw "Firefox exact-corpus E2E failed" }

& .\.venv\Scripts\python.exe tests/e2e/run_active_writer_e2e.py `
    --engine firefox `
    --profile "${firefoxProfile}-active-writer" `
    --browser-id "firefox"
if ($LASTEXITCODE -ne 0) { throw "Firefox active-writer E2E failed" }

& .\.venv\Scripts\python.exe tests/e2e/browser_coverage_contract.py core_firefox `
    --capability exact_set --capability active_writer --capability detailed `
    --surface rust --surface python --surface node --surface cli
if ($LASTEXITCODE -ne 0) { throw "Firefox depth receipt failed" }

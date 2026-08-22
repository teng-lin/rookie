$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:targetBrowser = if ($env:ROOKIE_E2E_TARGET_BROWSER) { $env:ROOKIE_E2E_TARGET_BROWSER.ToLower() } else { "chrome" }
$script:processNames = @{
  chrome = "chrome"
  edge = "msedge"
  brave = "brave"
  coccoc = "browser"
  avast = "AvastBrowser"
}
if (-not $script:processNames.ContainsKey($script:targetBrowser)) {
  throw "unsupported ROOKIE_E2E_TARGET_BROWSER '$($script:targetBrowser)'"
}
$script:browserProcess = $script:processNames[$script:targetBrowser]
$script:browserPath = if ($env:ROOKIE_E2E_BROWSER_PATH) { $env:ROOKIE_E2E_BROWSER_PATH } else { $env:ROOKIE_E2E_CHROME_PATH }

function Get-RequestLogSnapshot {
  if (-not (Test-Path $env:ROOKIE_E2E_REQUEST_LOG)) { return "<no request log>" }
  $entries = @(Get-Content $env:ROOKIE_E2E_REQUEST_LOG)
  if ($entries.Count -eq 0) { return "<empty>" }
  return ($entries -join ", ")
}

function Wait-ForRequest([string]$requestPath) {
  for ($i = 1; $i -le 240; $i++) {
    if ((Test-Path $env:ROOKIE_E2E_REQUEST_LOG) -and
        (Select-String -Path $env:ROOKIE_E2E_REQUEST_LOG `
          -Pattern "^$([regex]::Escape($requestPath))" -Quiet)) {
      return
    }
    Start-Sleep -Milliseconds 500
  }
  throw ("$script:targetBrowser did not request $requestPath within 120 seconds " +
    "(requests seen: $(Get-RequestLogSnapshot))")
}

function Wait-ForBrowser {
  for ($i = 1; $i -le 120; $i++) {
    $processes = @(Get-Process $script:browserProcess -ErrorAction SilentlyContinue)
    if ($processes.Count -gt 0) { return }
    Start-Sleep -Milliseconds 500
  }
  throw "$script:targetBrowser did not start"
}

function Get-BrowserMainWindows {
  return @(Get-Process $script:browserProcess -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 })
}

function Close-BrowserGracefully {
  $windows = @(Get-BrowserMainWindows)
  if ($windows.Count -eq 0) {
    throw "$script:targetBrowser has no main window to close"
  }
  foreach ($window in $windows) {
    [void]$window.CloseMainWindow()
  }
  for ($i = 1; $i -le 120; $i++) {
    if (-not (Get-Process $script:browserProcess -ErrorAction SilentlyContinue)) { return }
    Start-Sleep -Milliseconds 500
  }

  # Chromium forks (especially Brave) often keep crashpad/GPU/utility
  # processes after the last window closes. The graceful close already
  # proved the product did not kill the live browser during extraction.
  $leftover = @(Get-Process $script:browserProcess -ErrorAction SilentlyContinue)
  if ($leftover.Count -eq 0) { return }
  Write-Host ("{0} still had {1} process(es) after CloseMainWindow; stopping leftovers" -f `
    $script:targetBrowser, $leftover.Count)
  $leftover | Stop-Process -Force -ErrorAction SilentlyContinue
  for ($i = 1; $i -le 40; $i++) {
    if (-not (Get-Process $script:browserProcess -ErrorAction SilentlyContinue)) { return }
    Start-Sleep -Milliseconds 250
  }
  throw "$script:targetBrowser did not exit after a graceful window close"
}

function Wait-ForBrowserMainWindow {
  for ($i = 1; $i -le 120; $i++) {
    $window = Get-BrowserMainWindows | Select-Object -First 1
    if ($null -ne $window) { return $window }
    Start-Sleep -Milliseconds 500
  }
  throw "$script:targetBrowser has no closeable main window"
}

function Assert-BrowserAlive {
  $browser = Get-Process -Id $script:liveBrowserPid -ErrorAction SilentlyContinue
  if (($null -eq $browser) -or
      ($browser.StartTime -ne $script:liveBrowserStartTime)) {
    throw "rookie-cookies terminated the live $script:targetBrowser browser process"
  }
  Write-Host "$script:targetBrowser browser remains alive (pid: $($script:liveBrowserPid))"
}

foreach ($requiredVariable in @(
  "ROOKIE_E2E_REQUEST_LOG",
  "ROOKIE_E2E_USER_DATA_DIR",
  "ROOKIE_E2E_WINDOWS_SID"
)) {
  $requiredValue = [Environment]::GetEnvironmentVariable($requiredVariable)
  if ([string]::IsNullOrWhiteSpace($requiredValue)) {
    throw "required environment variable $requiredVariable is not set"
  }
}
if ([string]::IsNullOrWhiteSpace($script:browserPath)) {
  throw "neither ROOKIE_E2E_BROWSER_PATH nor ROOKIE_E2E_CHROME_PATH is set"
}

$server = $null
$walFixtureUserData = Join-Path $env:RUNNER_TEMP "rookie-appbound-wal-$PID"
Remove-Item $env:ROOKIE_E2E_REQUEST_LOG -Force -ErrorAction SilentlyContinue
Remove-Item $walFixtureUserData -Recurse -Force -ErrorAction SilentlyContinue
$server = Start-Process python `
  -ArgumentList "tests/e2e/cookie_server.py" -PassThru
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

  Write-Host "Identity before direct $script:targetBrowser seed:"
  whoami /user
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($currentSid -ne $env:ROOKIE_E2E_WINDOWS_SID) {
    throw "$script:targetBrowser seed user differs from the preflight user"
  }

  # No Playwright, CDP, remote-debugging, or --user-data-dir: this is the
  # machine install opening its real default profile directly.
  Start-Process -FilePath $script:browserPath -ArgumentList @(
    "--no-first-run",
    "--new-window",
    "--disable-background-mode",
    "--disable-background-networking",
    "--disable-backgrounding-occluded-windows",
    "--disable-features=BackgroundMode",
    "--disable-component-update",
    "--disable-sync",
    "http://127.0.0.1:8765/set"
  ) | Out-Null
  Wait-ForBrowser
  Wait-ForRequest "/set"

  $defaultDir = Join-Path $env:ROOKIE_E2E_USER_DATA_DIR "Default"
  $cookiesDb = Join-Path $defaultDir "Network\Cookies"
  for ($i = 1; $i -le 120; $i++) {
    if (Test-Path $cookiesDb) { break }
    $legacyDb = Join-Path $defaultDir "Cookies"
    if (Test-Path $legacyDb) { $cookiesDb = $legacyDb; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not (Test-Path $cookiesDb)) {
    throw "$script:targetBrowser did not create its Cookies database"
  }
  Start-Sleep -Seconds 2
  Close-BrowserGracefully

  $localState = Join-Path $env:ROOKIE_E2E_USER_DATA_DIR "Local State"
  if (-not (Test-Path $localState)) {
    throw "$script:targetBrowser did not create Local State"
  }
  & .\.venv\Scripts\python.exe tests/e2e/inspect_chromium_profile.py `
    "$env:ROOKIE_E2E_USER_DATA_DIR" --cookie-name rookie_ci `
    --expected-prefix v20 --require-app-bound-key
  if ($LASTEXITCODE -ne 0) { throw "strict v20 profile check failed" }

  # Current Chromium deliberately opens its cookie store in rollback-journal
  # mode, so it cannot itself provide a deterministic WAL-only row. Copy the
  # real database and stage its real App-Bound encrypted value under a new name
  # in a WAL. The stager exits without checkpointing, leaving both files
  # unlocked for the product's raw snapshot path.
  $walCookiesDb = Join-Path $walFixtureUserData "Default\Network\Cookies"
  Write-Host "STAGED_WAL_PROOF: copied synthetic DB+WAL fixture; not the active browser database"
  & .\.venv\Scripts\python.exe tests/e2e/stage_sqlite_wal_fixture.py `
    "$cookiesDb" "$walCookiesDb" --source-cookie rookie_ci `
    --fixture-cookie rookie_wal
  if ($LASTEXITCODE -ne 0) { throw "could not stage App-Bound WAL fixture" }
  Copy-Item -LiteralPath $localState `
    -Destination (Join-Path $walFixtureUserData "Local State")

  # Reopen the same default profile and leave browser running. /wal sets a
  # second real cookie as a browser-liveness signal during extraction.
  Start-Process -FilePath $script:browserPath -ArgumentList @(
    "--no-first-run",
    "--new-window",
    "--disable-background-mode",
    "--disable-background-networking",
    "--disable-backgrounding-occluded-windows",
    "--disable-features=BackgroundMode",
    "--disable-component-update",
    "--disable-sync",
    "http://127.0.0.1:8765/wal"
  ) | Out-Null
  Wait-ForBrowser
  Wait-ForRequest "/wal"

  $liveBrowser = Wait-ForBrowserMainWindow
  $script:liveBrowserPid = $liveBrowser.Id
  $script:liveBrowserStartTime = $liveBrowser.StartTime

  & .\.venv\Scripts\python.exe tests/e2e/inspect_chromium_profile.py `
    "$walFixtureUserData" --cookie-name rookie_wal `
    --expected-prefix v20 --require-app-bound-key --require-wal-only
  if ($LASTEXITCODE -ne 0) { throw "strict WAL-only v20 fixture check failed" }

  $env:ROOKIE_E2E_COOKIE_DB = $walCookiesDb
  $env:ROOKIE_E2E_COOKIE_NAME = "rookie_wal"
  $env:ROOKIE_E2E_COOKIE_VALUE = "bar"
  $env:ROOKIE_E2E_CHECK_BROWSER_DISCOVERY = "0"
  $env:ROOKIE_E2E_DISCOVERY_COOKIE_NAME = "rookie_ci"
  $env:ROOKIE_E2E_DISCOVERY_COOKIE_VALUE = "bar"

  Write-Host "Identity before extraction:"
  whoami /user
  $extractSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($extractSid -ne $env:ROOKIE_E2E_WINDOWS_SID) {
    throw "extraction user differs from the $script:targetBrowser seed user"
  }

  Write-Host "=== PASS 1: Test COM Injection ONLY (no elevation fallback) ==="
  # ROOKIE_E2E_APPBOUND_MODE no longer steers a published build: it is compiled
  # in only under cfg(test) or the off-by-default `e2e-appbound-steering`
  # feature, and even then it can only narrow the request's own AppBoundPolicy.
  # The Rust pass therefore needs the feature; the Python/Node/CLI passes ask
  # for the policy through their public surface instead.
  $env:ROOKIE_E2E_APPBOUND_MODE = "injection_only"

  cargo test --features e2e-appbound-steering --test e2e_chrome -- extracts_seeded_cookie_via_injection_only --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw "Rust App-Bound COM injection (injection_only) failed" }
  Assert-BrowserAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_chrome_cookie.py
  if ($LASTEXITCODE -ne 0) { throw "Python App-Bound COM injection (injection_only) failed" }
  Assert-BrowserAlive

  node tests/e2e/assert_chrome_cookie.mjs
  if ($LASTEXITCODE -ne 0) { throw "Node App-Bound COM injection (injection_only) failed" }
  Assert-BrowserAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py `
    "$walCookiesDb" --local-state-path "$localState"
  if ($LASTEXITCODE -ne 0) { throw "CLI App-Bound COM injection (injection_only) failed" }
  Assert-BrowserAlive

  Write-Host "=== PASS 2: Test Elevated DPAPI Fallback ONLY (no COM injection) ==="
  # "Skip the unprivileged attempt" is deliberately not a public policy value,
  # so this pass is the one place the steering feature is required rather than
  # merely convenient.
  $env:ROOKIE_E2E_APPBOUND_MODE = "elevated_only"

  cargo test --features e2e-appbound-steering --test e2e_chrome -- extracts_seeded_cookie_via_elevated_fallback_only --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw "Rust App-Bound elevated fallback (elevated_only) failed" }
  Assert-BrowserAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_chrome_cookie.py
  if ($LASTEXITCODE -ne 0) { throw "Python App-Bound elevated fallback (elevated_only) failed" }
  Assert-BrowserAlive

  node tests/e2e/assert_chrome_cookie.mjs
  if ($LASTEXITCODE -ne 0) { throw "Node App-Bound elevated fallback (elevated_only) failed" }
  Assert-BrowserAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py `
    "$walCookiesDb" --local-state-path "$localState"
  if ($LASTEXITCODE -ne 0) { throw "CLI App-Bound elevated fallback (elevated_only) failed" }
  Assert-BrowserAlive

  Write-Host "=== PASS 3: Test Default $script:targetBrowser Discovery (Auto Mode) ==="
  Remove-Item Env:\ROOKIE_E2E_APPBOUND_MODE -ErrorAction SilentlyContinue

  # Close browser through its window only after every surface has proved
  # the WAL fixture can be read without killing the live browser.
  Close-BrowserGracefully
  Remove-Item Env:\ROOKIE_E2E_COOKIE_DB
  $env:ROOKIE_E2E_COOKIE_NAME = "rookie_ci"
  $env:ROOKIE_E2E_COOKIE_VALUE = "bar"
  $env:ROOKIE_E2E_CHECK_BROWSER_DISCOVERY = "1"

  cargo test --test e2e_chrome `
    extracts_seeded_cookie_through_default_chrome_discovery `
    -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw "Rust App-Bound $script:targetBrowser discovery failed" }

  & .\.venv\Scripts\python.exe tests/e2e/assert_chrome_cookie.py
  if ($LASTEXITCODE -ne 0) { throw "Python App-Bound $script:targetBrowser discovery failed" }

  node tests/e2e/assert_chrome_cookie.mjs
  if ($LASTEXITCODE -ne 0) { throw "Node App-Bound $script:targetBrowser discovery failed" }

  & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py --browser "$script:targetBrowser"
  if ($LASTEXITCODE -ne 0) { throw "CLI App-Bound $script:targetBrowser discovery failed" }
} finally {
  Get-Process $script:browserProcess -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  if ($null -ne $server) {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item $walFixtureUserData -Recurse -Force -ErrorAction SilentlyContinue
}

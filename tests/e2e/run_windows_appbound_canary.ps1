$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Wait-ForRequest([string]$requestPath) {
  for ($i = 1; $i -le 120; $i++) {
    if ((Test-Path $env:ROOKIE_E2E_REQUEST_LOG) -and
        (Select-String -Path $env:ROOKIE_E2E_REQUEST_LOG `
          -Pattern "^$([regex]::Escape($requestPath))" -Quiet)) {
      return
    }
    Start-Sleep -Milliseconds 500
  }
  throw "Chrome did not request $requestPath within 60 seconds"
}

function Wait-ForChrome {
  for ($i = 1; $i -le 60; $i++) {
    $processes = @(Get-Process chrome -ErrorAction SilentlyContinue)
    if ($processes.Count -gt 0) { return }
    Start-Sleep -Milliseconds 500
  }
  throw "Chrome did not start"
}

function Close-ChromeGracefully {
  $windows = @(Get-Process chrome -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 })
  if ($windows.Count -eq 0) {
    throw "Chrome has no closeable main window"
  }
  foreach ($window in $windows) {
    [void]$window.CloseMainWindow()
  }
  for ($i = 1; $i -le 60; $i++) {
    if (-not (Get-Process chrome -ErrorAction SilentlyContinue)) { return }
    Start-Sleep -Milliseconds 500
  }
  throw "Chrome did not exit after a graceful window close"
}

function Wait-ForChromeMainWindow {
  for ($i = 1; $i -le 60; $i++) {
    $window = Get-Process chrome -ErrorAction SilentlyContinue |
      Where-Object { $_.MainWindowHandle -ne 0 } |
      Select-Object -First 1
    if ($null -ne $window) { return $window }
    Start-Sleep -Milliseconds 500
  }
  throw "Chrome has no closeable main window"
}

function Assert-ChromeAlive {
  $browser = Get-Process -Id $script:liveBrowserPid -ErrorAction SilentlyContinue
  if (($null -eq $browser) -or
      ($browser.StartTime -ne $script:liveBrowserStartTime)) {
    throw "rookie-cookies terminated the live Chrome browser process"
  }
  Write-Host "Chrome browser remains alive (pid: $($script:liveBrowserPid))"
}

Remove-Item $env:ROOKIE_E2E_REQUEST_LOG -Force -ErrorAction SilentlyContinue
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

  Write-Host "Identity before direct Chrome seed:"
  whoami /user
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($currentSid -ne $env:ROOKIE_E2E_WINDOWS_SID) {
    throw "Chrome seed user differs from the preflight user"
  }

  # No Playwright, CDP, remote-debugging, or --user-data-dir: this is the
  # machine install opening its real default profile directly.
  Start-Process -FilePath $env:ROOKIE_E2E_CHROME_PATH -ArgumentList @(
    "--no-first-run",
    "--disable-background-mode",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "http://127.0.0.1:8765/set"
  ) | Out-Null
  Wait-ForChrome
  Wait-ForRequest "/set"

  $defaultDir = Join-Path $env:ROOKIE_E2E_USER_DATA_DIR "Default"
  $cookiesDb = Join-Path $defaultDir "Network\Cookies"
  for ($i = 1; $i -le 60; $i++) {
    if (Test-Path $cookiesDb) { break }
    $legacyDb = Join-Path $defaultDir "Cookies"
    if (Test-Path $legacyDb) { $cookiesDb = $legacyDb; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not (Test-Path $cookiesDb)) {
    throw "Chrome did not create its Cookies database"
  }
  Start-Sleep -Seconds 2
  Close-ChromeGracefully

  $localState = Join-Path $env:ROOKIE_E2E_USER_DATA_DIR "Local State"
  if (-not (Test-Path $localState)) {
    throw "Chrome did not create Local State"
  }
  & .\.venv\Scripts\python.exe tests/e2e/inspect_chromium_profile.py `
    "$env:ROOKIE_E2E_USER_DATA_DIR" --cookie-name rookie_ci `
    --expected-prefix v20 --require-app-bound-key
  if ($LASTEXITCODE -ne 0) { throw "strict v20 profile check failed" }

  # Reopen the same default profile and leave Chrome running. /wal sets a
  # unique cookie that every extraction surface must recover.
  Start-Process -FilePath $env:ROOKIE_E2E_CHROME_PATH -ArgumentList @(
    "--no-first-run",
    "--disable-background-mode",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "http://127.0.0.1:8765/wal"
  ) | Out-Null
  Wait-ForChrome
  Wait-ForRequest "/wal"

  $liveBrowser = Wait-ForChromeMainWindow
  $script:liveBrowserPid = $liveBrowser.Id
  $script:liveBrowserStartTime = $liveBrowser.StartTime

  $walPath = "$cookiesDb-wal"
  $walReady = $false
  for ($i = 1; $i -le 60; $i++) {
    if ((Test-Path $walPath) -and (Get-Item $walPath).Length -gt 0) {
      $walReady = $true
      break
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $walReady) {
    throw "live Chrome Cookies WAL is missing or empty"
  }
  Write-Host "Live Cookies WAL length: $((Get-Item $walPath).Length)"

  $walValidated = $false
  for ($i = 1; $i -le 60; $i++) {
    & .\.venv\Scripts\python.exe tests/e2e/inspect_chromium_profile.py `
      "$env:ROOKIE_E2E_USER_DATA_DIR" --cookie-name rookie_wal `
      --expected-prefix v20 --require-wal-only
    if ($LASTEXITCODE -eq 0) {
      $walValidated = $true
      break
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $walValidated) { throw "strict WAL-only v20 profile check failed" }

  $env:ROOKIE_E2E_COOKIE_NAME = "rookie_wal"
  $env:ROOKIE_E2E_COOKIE_VALUE = "live"
  $env:ROOKIE_E2E_CHECK_BROWSER_DISCOVERY = "1"

  Write-Host "Identity before elevated extraction:"
  whoami /user
  $extractSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($extractSid -ne $env:ROOKIE_E2E_WINDOWS_SID) {
    throw "extraction user differs from the Chrome seed user"
  }

  cargo test --test e2e_chrome -- --ignored --nocapture
  if ($LASTEXITCODE -ne 0) { throw "Rust App-Bound extraction failed" }
  Assert-ChromeAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_chrome_cookie.py
  if ($LASTEXITCODE -ne 0) { throw "Python App-Bound extraction failed" }
  Assert-ChromeAlive

  node tests/e2e/assert_chrome_cookie.mjs
  if ($LASTEXITCODE -ne 0) { throw "Node App-Bound extraction failed" }
  Assert-ChromeAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py `
    "$cookiesDb" --key-path "$localState"
  if ($LASTEXITCODE -ne 0) { throw "CLI App-Bound extraction failed" }
  Assert-ChromeAlive

  & .\.venv\Scripts\python.exe tests/e2e/assert_cli_cookie.py --browser chrome
  if ($LASTEXITCODE -ne 0) { throw "CLI App-Bound Chrome discovery failed" }
  Assert-ChromeAlive
} finally {
  # The canary uses only its fake-cookie profile on an ephemeral runner.
  # Profiles and Local State are never uploaded.
  Get-Process chrome -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}

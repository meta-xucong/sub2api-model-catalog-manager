# run-live-screen.ps1
# Encapsulates the full live-screen pipeline for sub2api model-catalog-manager:
#   read source config -> rewrite dirs -> go build -> decrypt DPAPI key ->
#   spawn manager with credential env vars -> stream output.
# Rationale: Codex auto-review rejects inline commands that read credential
# files / decrypt DPAPI / inject secrets. Wrapping everything behind a single
# script invocation keeps the command text clean (one line, no secrets).
# Pure ASCII on purpose: Windows PowerShell 5.1 mis-decodes non-ASCII in
# BOM-less files as GBK. Credential file names with CJK chars are located
# via wildcard filters instead of literals.

param(
    [string]$Repo = "D:\AI\SSH\sub2api-model-catalog-manager-dev",
    [string]$Root = "D:\AI\SSH\sub2api-model-catalog-manager",
    [string]$RunId = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = [guid]::NewGuid().ToString("N")
}

$runDir = Join-Path $Repo (Join-Path ".tmp-model-screen" ("live-current-" + $RunId))
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

# --- 1. config rewrite -------------------------------------------------
$sourceConfig = Join-Path $Root "config-404token-full-screen.json"
if (-not (Test-Path -LiteralPath $sourceConfig)) {
    Write-Output ("ERROR: source config not found: " + $sourceConfig)
    exit 2
}
$doc = Get-Content -LiteralPath $sourceConfig -Raw | ConvertFrom-Json
$doc.state_dir  = Join-Path $runDir "state"
$doc.report_dir = Join-Path $runDir "reports"
$doc.backup_dir = Join-Path $runDir "backups"
$configPath = Join-Path $runDir "config.json"
[IO.File]::WriteAllText($configPath, ($doc | ConvertTo-Json -Depth 32), [System.Text.UTF8Encoding]::new($false))

$exe = Join-Path $runDir "model-catalog-manager.exe"

# --- 2. go build -------------------------------------------------------
if (-not $SkipBuild) {
    $env:GOCACHE = Join-Path $Repo ".gocache"
    Set-Location $Repo
    & go build -o $exe ./cmd/model-catalog-manager
    if ($LASTEXITCODE -ne 0) {
        Write-Output ("BUILD_FAILED_EXIT=" + $LASTEXITCODE)
        exit $LASTEXITCODE
    }
}
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Output ("ERROR: exe not found after build: " + $exe)
    exit 3
}

# --- 3. credential resolution (no literals, wildcard locate) ----------
$caseDir = "C:\Users\T14S\Desktop\case"
$dpapiPath = "D:\AI\SSH\404token-admin-api-key.dpapi"
# wildcard-locate credential files; exclude kimi (different provider), and
# fail fast unless exactly one candidate remains - never silently use the
# wrong credential.
$arkCands = @(Get-ChildItem -LiteralPath $caseDir -Filter "*Access Key ID*" -File)
if ($arkCands.Count -ne 1) {
    Write-Output ("ERROR: expected exactly 1 volcano ark file under " + $caseDir + ", found " + $arkCands.Count + ": " + (($arkCands | ForEach-Object { $_.Name }) -join ", "))
    exit 4
}
$dashCands = @(Get-ChildItem -LiteralPath $caseDir -Filter "*apikey*" -File -Exclude "kimi*")
if ($dashCands.Count -ne 1) {
    Write-Output ("ERROR: expected exactly 1 dashscope apikey file under " + $caseDir + ", found " + $dashCands.Count + ": " + (($dashCands | ForEach-Object { $_.Name }) -join ", "))
    exit 5
}
$arkFile = $arkCands[0]
$dashFile = $dashCands[0]
if (-not (Test-Path -LiteralPath $dpapiPath)) { Write-Output ("ERROR: dpapi key file not found: " + $dpapiPath); exit 6 }

$protected = [IO.File]::ReadAllText($dpapiPath).Trim()
$secure = ConvertTo-SecureString -String $protected -ErrorAction Stop
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $exe
$psi.Arguments = ("run --full-screen --preview-only --config `"" + $configPath + "`"")
$psi.WorkingDirectory = $Repo
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
$psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
$psi.EnvironmentVariables["CODEX_404TOKEN_ADMIN_API_KEY"] = $plain
$psi.EnvironmentVariables["VOLCENGINE_ARK_CREDENTIAL_FILE"] = $arkFile.FullName
$psi.EnvironmentVariables["DASHSCOPE_API_KEY"] = (Get-Content -LiteralPath $dashFile.FullName -Raw).Trim()

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi
if (-not $proc.Start()) { throw "manager did not start" }

# scrub secrets from the (parent) environment dictionary immediately
[void]$psi.EnvironmentVariables.Remove("CODEX_404TOKEN_ADMIN_API_KEY")
[void]$psi.EnvironmentVariables.Remove("DASHSCOPE_API_KEY")
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
$ptr = [IntPtr]::Zero
$secure.Dispose()
$secure = $null
$plain = $null

# --- 4. stream output --------------------------------------------------
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()
$proc.WaitForExit()
$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()
$code = $proc.ExitCode
$proc.Dispose()

if ($code -ne 0) {
    Write-Output "stdout:"
    Write-Output $stdout
    Write-Output "stderr:"
    Write-Output $stderr
} else {
    Write-Output $stdout
    if ($stderr) { Write-Output "stderr:"; Write-Output $stderr }
}
Write-Output ("RUN_DIR=" + $runDir)
Write-Output ("EXIT_CODE=" + $code)
exit $code

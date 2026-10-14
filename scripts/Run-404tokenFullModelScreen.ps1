param(
    [switch]$PreviewOnly
)

$ErrorActionPreference = 'Stop'

$managerRoot = Split-Path -Parent $PSScriptRoot
$executable = Join-Path $managerRoot 'bin\model-catalog-manager-full-screen.exe'
$configuration = Join-Path $managerRoot 'config-404token-full-screen.json'
$protectedKeyPath = Join-Path (Join-Path $managerRoot 'secrets') '404token-admin-api-key.dpapi'
$logDirectory = Join-Path $managerRoot 'logs'

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'The full-screen model catalog manager executable is unavailable.'
}
if (-not (Test-Path -LiteralPath $configuration -PathType Leaf)) {
    throw 'The 404token full-screen configuration is unavailable.'
}
if ($configuration.Contains('"')) {
    throw 'The 404token configuration path contains an unsupported quote character.'
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$logPath = Join-Path $logDirectory ('full-screen-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$exitCode = 1

function Write-RunLogLine {
    param([string]$Text)
    [IO.File]::AppendAllText($logPath, $Text + "`r`n", $utf8NoBom)
}

function Write-RunLogStream {
    param([string]$StreamName, [string]$Content)
    foreach ($line in ($Content -split "`r?`n")) {
        if ($line.Length -gt 0) {
            Write-RunLogLine ("[{0}] {1}" -f $StreamName, $line)
        }
    }
}

Write-RunLogLine "[$(Get-Date -Format o)] starting 404token full-account model screening; preview_only=$($PreviewOnly.IsPresent)"
$process = New-Object System.Diagnostics.Process
$started = $false
$secureKey = $null
$plainKey = $null
$keyPointer = [IntPtr]::Zero
$startInfo = $null
try {
    if (-not (Test-Path -LiteralPath $protectedKeyPath -PathType Leaf)) {
        throw 'The user-protected 404token API key file is unavailable.'
    }
    $protectedKey = [IO.File]::ReadAllText($protectedKeyPath).Trim()
    if (-not $protectedKey) {
        throw 'The user-protected 404token API key file is empty.'
    }
    $secureKey = ConvertTo-SecureString -String $protectedKey -ErrorAction Stop
    $keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
    if ([string]::IsNullOrWhiteSpace($plainKey) -or $plainKey.Length -gt 16384 -or $plainKey -match '\s') {
        throw 'The decrypted 404token API key has an invalid shape.'
    }

    $arguments = 'run --full-screen --config "{0}"' -f $configuration
    if ($PreviewOnly) {
        $arguments += ' --preview-only'
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $executable
    $startInfo.Arguments = $arguments
    $startInfo.WorkingDirectory = $managerRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = $utf8NoBom
    $startInfo.StandardErrorEncoding = $utf8NoBom
    $startInfo.EnvironmentVariables['CODEX_404TOKEN_ADMIN_API_KEY'] = $plainKey
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'The model catalog manager process did not start.'
    }
    $started = $true
    [void]$startInfo.EnvironmentVariables.Remove('CODEX_404TOKEN_ADMIN_API_KEY')
    if ($keyPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
        $keyPointer = [IntPtr]::Zero
    }
    if ($secureKey) {
        $secureKey.Dispose()
        $secureKey = $null
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()

    if ($plainKey) {
        $escapedKey = [regex]::Escape($plainKey)
        $stdout = [regex]::Replace($stdout, $escapedKey, '[REDACTED]')
        $stderr = [regex]::Replace($stderr, $escapedKey, '[REDACTED]')
    }
    Write-RunLogStream 'stdout' $stdout
    Write-RunLogStream 'stderr' $stderr
    $exitCode = $process.ExitCode
    if ($exitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($stderr)) {
        Write-Output 'Model screening error:'
        Write-Output $stderr.Trim()
    }

    if ($exitCode -eq 0) {
        $summaryMatch = [regex]::Match($stdout, '(?m)^summary_path_json=(?<path>.+)$')
        if ($summaryMatch.Success) {
            try {
                $summaryPath = ConvertFrom-Json -InputObject $summaryMatch.Groups['path'].Value -ErrorAction Stop
                if ($summaryPath -isnot [string] -or [string]::IsNullOrWhiteSpace($summaryPath)) {
                    throw 'Manager summary path is not a JSON string.'
                }

                $summaryFullPath = [IO.Path]::GetFullPath($summaryPath)
                $configDocument = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json -ErrorAction Stop
                $configuredReportDir = [string]$configDocument.report_dir
                if ([string]::IsNullOrWhiteSpace($configuredReportDir)) {
                    throw 'Configured report directory is empty.'
                }
                if (-not [IO.Path]::IsPathRooted($configuredReportDir)) {
                    $configuredReportDir = Join-Path $managerRoot $configuredReportDir
                }
                $reportRoot = [IO.Path]::GetFullPath($configuredReportDir).TrimEnd([char[]]@('\', '/'))
                $reportPrefix = $reportRoot + [IO.Path]::DirectorySeparatorChar
                if (-not $summaryFullPath.StartsWith($reportPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Manager summary path is outside the configured report directory.'
                }
                if ([IO.Path]::GetFileName($summaryFullPath) -notmatch '^screen-summary-\d{8}T\d{6}Z-[a-f0-9]{32}\.md$') {
                    throw 'Manager summary filename does not match the expected pattern.'
                }
                if (-not (Test-Path -LiteralPath $summaryFullPath -PathType Leaf)) {
                    throw 'Manager summary file does not exist.'
                }

                Write-Output "Summary: $summaryFullPath"
                try {
                    Invoke-Item -LiteralPath $summaryFullPath -ErrorAction Stop
                } catch {
                    Write-Output 'The summary was saved, but Windows could not open it with the default file association.'
                    Write-RunLogLine ("[summary-open-error] {0}" -f $_.Exception.Message)
                }
            } catch {
                Write-Output 'The summary path could not be validated; see the run log for details.'
                Write-RunLogLine ("[summary-validation-error] {0}" -f $_.Exception.Message)
            }
        }
    }
} catch {
    Write-RunLogLine ("[wrapper-error] {0}" -f $_.Exception.Message)
    if ($started) {
        try { $process.WaitForExit() } catch { }
    }
} finally {
    if ($startInfo) {
        [void]$startInfo.EnvironmentVariables.Remove('CODEX_404TOKEN_ADMIN_API_KEY')
    }
    if ($keyPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
    }
    if ($secureKey) {
        $secureKey.Dispose()
    }
    $plainKey = $null
    $protectedKey = $null
    $process.Dispose()
}

Write-RunLogLine "[$(Get-Date -Format o)] finished with exit code $exitCode"
Write-Output "Full-screen run exit code: $exitCode"
Write-Output "Log: $logPath"
exit $exitCode

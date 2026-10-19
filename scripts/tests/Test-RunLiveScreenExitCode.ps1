$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runner = Join-Path $repo "scripts\run-live-screen.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Screen runner has PowerShell parse errors: $($parseErrors[0].Message)"
}
$exitStatements = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true)
if ($exitStatements.Count -eq 0 -or $exitStatements[-1].Pipeline.PipelineElements[0].Expression.Extent.Text -ne '$code') {
    throw "Screen runner must exit with the manager process code."
}

$probePath = Join-Path ([IO.Path]::GetTempPath()) ("codex-exit-code-" + [guid]::NewGuid().ToString("N") + ".ps1")
try {
    [IO.File]::WriteAllText($probePath, '$code = 23' + [Environment]::NewLine + 'exit $code')
    $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @("-NoProfile", "-File", $probePath) -PassThru -Wait
    if ($process.ExitCode -ne 23) {
        throw "PowerShell did not propagate the simulated manager exit code: $($process.ExitCode)"
    }
} finally {
    Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
}

Write-Output "PASS: screen runner propagates manager exit codes."

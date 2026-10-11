#Requires -Version 5.1
<#
.SYNOPSIS
    Re-runs the checks marked needsAdmin in an existing findings.json with administrator rights
    (one UAC prompt) and merges the results into that file. Read-only, like the collector.
.OUTPUTS
    One line starting with OK, DECLINED, TIMEOUT or FAILED. Exit codes: 0 / 3 / 4 / 5.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $FindingsPath,
    [int] $TimeoutSeconds = 240
)
$ErrorActionPreference = 'Stop'

$FindingsPath = (Resolve-Path $FindingsPath).Path
$collector = Join-Path $PSScriptRoot 'Invoke-SecurityAudit.ps1'
$merged = [IO.Path]::ChangeExtension($FindingsPath, '.admin.json')
$argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$collector`" -OutputPath `"$merged`" -BasePath `"$FindingsPath`""

try {
    $p = Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $argLine -WindowStyle Hidden -PassThru
} catch {
    Write-Output 'DECLINED: the administrator prompt was cancelled; admin-only checks stay "needs admin".'
    exit 3
}
if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    Write-Output "TIMEOUT: the elevated check did not finish within $TimeoutSeconds seconds."
    exit 4
}
if (-not (Test-Path $merged)) {
    Write-Output 'FAILED: the elevated check produced no output.'
    exit 5
}
Move-Item -Path $merged -Destination $FindingsPath -Force
Write-Output "OK: admin-only checks merged into $FindingsPath"
exit 0

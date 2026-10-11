#Requires -Version 5.1
<#
.SYNOPSIS
    Prints the newest audit session folder and its numbered findings. Read-only.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:USERPROFILE 'WindowsSecurityAudit'
$session = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{6}$' -and (Test-Path (Join-Path $_.FullName 'findings.json')) } |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $session) {
    Write-Output "NO_SESSION: no audit found under $root"
    exit 1
}

$doc = [IO.File]::ReadAllText((Join-Path $session.FullName 'findings.json')) | ConvertFrom-Json
Write-Output "Session: $($session.FullName)"
Write-Output "Audited (UTC): $($doc.meta.generatedUtc) | context: $($doc.meta.context) | report.md: $(Test-Path (Join-Path $session.FullName 'report.md')) | changes.json: $(Test-Path (Join-Path $session.FullName 'changes.json'))"
Write-Output 'number | id | severity | fix | title'
@($doc.checks | Where-Object { $_.number } | Sort-Object { [int]$_.number }) | ForEach-Object {
    Write-Output ('{0} | {1} | {2} | {3} | {4}' -f $_.number, $_.id, $_.severity, $_.fix, $_.title)
}

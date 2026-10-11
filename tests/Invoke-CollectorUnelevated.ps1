#Requires -Version 5.1
<#
.SYNOPSIS
    Test helper: runs the collector with the user's normal (non-elevated) token, even when called from an
    elevated session, by launching it through explorer.exe. Waits for findings.json and prints its path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputDir,
    [ValidateSet('Mobile', 'Stationary')] [string] $Context = 'Stationary',
    [int] $TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$collector = Join-Path $PSScriptRoot '..\scripts\Invoke-SecurityAudit.ps1' | Resolve-Path
$findings = Join-Path $OutputDir 'findings.json'
$log = Join-Path $OutputDir 'collector.log'
$cmd = Join-Path $OutputDir 'run-unelevated.cmd'
"@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$collector`" -OutputPath `"$findings`" -Context $Context > `"$log`" 2>&1" |
    Set-Content -Encoding ASCII $cmd

Start-Process explorer.exe -ArgumentList "`"$cmd`""
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not (Test-Path $findings) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $findings)) { throw "Collector produced no output within $TimeoutSeconds s. Log: $log" }
Start-Sleep -Milliseconds 300   # let the writer close the file
$findings

#Requires -Version 5.1
<#
.SYNOPSIS
    Applies, previews or undoes the automated fixes for audit findings.
.DESCRIPTION
    Only fixes defined in scripts\fixes\*.ps1 can run; anything else is reported as NOT_AUTOMATED.
    Apply records the previous state in <session>\changes.json first, then changes the setting and re-runs
    the matching check to verify. Rollback restores exactly the recorded previous state.
.PARAMETER Ids
    Check IDs to fix, e.g. NET-16,DEF-06.
.PARAMETER Mode
    DryRun (default) shows what would change; Apply changes it; Rollback undoes the last Apply.
.PARAMETER SessionDir
    Audit session folder (default: the newest one under %USERPROFILE%\WindowsSecurityAudit).
.PARAMETER Elevate
    Run fixes that need administrator rights through one UAC prompt when not already elevated.
.OUTPUTS
    One line per fix: <ID> | <Mode> | <OK|FAILED|NEEDS_ADMIN|NOT_AUTOMATED|DECLINED|NOTHING_TO_UNDO> | details
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Ids,
    [ValidateSet('DryRun', 'Apply', 'Rollback')] [string] $Mode = 'DryRun',
    [string] $SessionDir,
    [switch] $Elevate,
    [string] $ResultPath   # internal: the elevated child writes its output lines here
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Ids = @($Ids | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })

if (-not $SessionDir) {
    $SessionDir = Get-ChildItem (Join-Path $env:USERPROFILE 'WindowsSecurityAudit') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{6}$' -and (Test-Path (Join-Path $_.FullName 'findings.json')) } | Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $SessionDir) { Write-Output 'FAILED: no audit session found; run the audit first.'; exit 1 }
}
$SessionDir = (Resolve-Path $SessionDir).Path
$changesPath = Join-Path $SessionDir 'changes.json'
$findingsPath = Join-Path $SessionDir 'findings.json'
$context = if (Test-Path $findingsPath) { ([IO.File]::ReadAllText($findingsPath) | ConvertFrom-Json).meta.context } else { 'Mobile' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# --- fix registry ------------------------------------------------------------------------------------
$script:Fixes = @{}
function Register-Fix {
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('user', 'machine')] [string] $Scope,
        [Parameter(Mandatory)] [scriptblock] $Describe,   # param($state) -> text of the planned change
        [Parameter(Mandatory)] [scriptblock] $GetState,   # -> hashtable of the values the fix changes
        [Parameter(Mandatory)] [scriptblock] $Apply,
        [Parameter(Mandatory)] [scriptblock] $Restore,    # param($prior) -> restores exactly $prior
        [switch] $MayNeedRestart
    )
    $script:Fixes[$Id] = [pscustomobject]@{
        Id = $Id; Scope = $Scope; Describe = $Describe; GetState = $GetState; Apply = $Apply; Restore = $Restore
        MayNeedRestart = [bool]$MayNeedRestart
    }
}

function Get-RegValue {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Name)
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) { $item.$Name } else { $null }
}

# Restores a registry value to a recorded state: $null means "value did not exist".
function Set-RegValueState {
    param([string] $Path, [string] $Name, $Value, [string] $Type = 'DWord')
    if ($null -eq $Value) {
        if ((Get-RegValue $Path $Name) -ne $null) { Remove-ItemProperty -Path $Path -Name $Name }
    } else {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

Get-ChildItem -Path (Join-Path $PSScriptRoot 'fixes') -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }

# --- helpers -----------------------------------------------------------------------------------------
function Read-Changes {
    if (-not (Test-Path $changesPath)) { return @() }
    # PS 5.1 ConvertFrom-Json emits a JSON array as one object; foreach enumerates it either way.
    $parsed = [IO.File]::ReadAllText($changesPath) | ConvertFrom-Json
    @(foreach ($entry in $parsed) { $entry })
}
function Add-Change {
    param([hashtable] $Entry)
    $all = @(Read-Changes) + @([pscustomobject]$Entry)
    [IO.File]::WriteAllText($changesPath, (ConvertTo-Json -InputObject $all -Depth 6), (New-Object Text.UTF8Encoding $false))
}
function ConvertTo-StateText {
    param($State)
    if ($null -eq $State) { return '(none)' }
    $h = if ($State -is [hashtable]) { $State } else { $t = @{}; $State.PSObject.Properties | ForEach-Object { $t[$_.Name] = $_.Value }; $t }
    (@($h.Keys | Sort-Object | ForEach-Object { "$_=$(if ($null -eq $h[$_]) { '(not set)' } else { $h[$_] })" }) -join ', ')
}
function Test-StateEqual {
    param($A, $B)
    (ConvertTo-StateText $A) -eq (ConvertTo-StateText $B)
}
# Re-runs the matching audit check; returns its status (pass/fail/...).
function Get-CheckStatus {
    param([string] $Id)
    $tmp = Join-Path $SessionDir "verify-$Id.json"
    & (Join-Path $PSScriptRoot 'Invoke-SecurityAudit.ps1') -OutputPath $tmp -Context $context -OnlyIds $Id | Out-Null
    $r = @(([IO.File]::ReadAllText($tmp) | ConvertFrom-Json).checks)[0]
    Remove-Item $tmp -Force
    $r
}

function Invoke-OneFix {
    param([string] $Id)
    $fix = $script:Fixes[$Id]
    $undo = "Invoke-SecurityFix.ps1 -Ids $Id -Mode Rollback"
    try {
        switch ($Mode) {
            'DryRun' {
                $state = & $fix.GetState
                "$Id | DryRun | OK | would: $(& $fix.Describe $state) | current: $(ConvertTo-StateText $state) | needs admin: $($fix.Scope -eq 'machine')"
            }
            'Apply' {
                $prior = & $fix.GetState
                Add-Change @{ id = $Id; mode = 'Apply'; status = 'started'; timeUtc = (Get-Date).ToUniversalTime().ToString('o'); user = $identity.Name; prior = $prior }
                try {
                    & $fix.Apply
                } catch {
                    # Never leave a half-applied change behind: put the recorded state back.
                    $applyError = $_.Exception.Message
                    & $fix.Restore $prior
                    Add-Change @{ id = $Id; mode = 'Apply'; status = 'reverted'; timeUtc = (Get-Date).ToUniversalTime().ToString('o'); user = $identity.Name; prior = $prior; after = (& $fix.GetState); error = $applyError }
                    return "$Id | Apply | FAILED | $applyError (previous state restored: $(ConvertTo-StateText (& $fix.GetState)))"
                }
                $check = Get-CheckStatus $Id
                $ok = $check.status -eq 'pass'
                $restart = $fix.MayNeedRestart -and [bool]$check.rebootRequired
                Add-Change @{ id = $Id; mode = 'Apply'; status = $(if ($ok) { 'applied' } else { 'unverified' }); timeUtc = (Get-Date).ToUniversalTime().ToString('o'); user = $identity.Name; prior = $prior; after = (& $fix.GetState); checkStatus = $check.status }
                "$Id | Apply | $(if ($ok) { 'OK' } else { 'FAILED' }) | check now: $($check.status) - $($check.summary)$(if ($restart) { ' | restart needed to finish' }) | undo: $undo"
            }
            'Rollback' {
                $last = @(Read-Changes | Where-Object { $_.id -eq $Id }) | Select-Object -Last 1
                if (-not $last -or $last.mode -ne 'Apply' -or $last.status -notin 'applied', 'unverified') {
                    return "$Id | Rollback | NOTHING_TO_UNDO | no completed change for $Id in $changesPath"
                }
                & $fix.Restore $last.prior
                $now = & $fix.GetState
                $ok = Test-StateEqual $now $last.prior
                Add-Change @{ id = $Id; mode = 'Rollback'; status = $(if ($ok) { 'restored' } else { 'mismatch' }); timeUtc = (Get-Date).ToUniversalTime().ToString('o'); user = $identity.Name; restoredTo = $last.prior; after = $now }
                "$Id | Rollback | $(if ($ok) { 'OK' } else { 'FAILED' }) | restored: $(ConvertTo-StateText $now) (recorded before: $(ConvertTo-StateText $last.prior))"
            }
        }
    } catch {
        "$Id | $Mode | FAILED | $($_.Exception.Message)"
    }
}

# --- run ---------------------------------------------------------------------------------------------
$lines = New-Object System.Collections.Generic.List[string]
$needElevation = New-Object System.Collections.Generic.List[string]
foreach ($id in $Ids) {
    $fix = $script:Fixes[$id]
    if (-not $fix) { $lines.Add("$id | $Mode | NOT_AUTOMATED | no automatic fix; follow the guided steps for $id"); continue }
    if ($Mode -ne 'DryRun' -and $fix.Scope -eq 'machine' -and -not $elevated) {
        if ($Elevate) { $needElevation.Add($id) } else { $lines.Add("$id | $Mode | NEEDS_ADMIN | rerun with -Elevate (one administrator prompt)") }
        continue
    }
    $lines.Add((Invoke-OneFix $id))
}

if ($needElevation.Count) {
    $childResult = Join-Path $SessionDir ("fix-result-{0}.txt" -f (Get-Date -Format 'HHmmssfff'))
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Ids $($needElevation -join ',') -Mode $Mode -SessionDir `"$SessionDir`" -ResultPath `"$childResult`""
    try {
        $p = Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $argLine -WindowStyle Hidden -PassThru
        if (-not $p.WaitForExit(300000)) { $needElevation | ForEach-Object { $lines.Add("$_ | $Mode | FAILED | timed out waiting for the elevated process") } }
        elseif (Test-Path $childResult) { [IO.File]::ReadAllLines($childResult) | ForEach-Object { $lines.Add($_) }; Remove-Item $childResult -Force }
        else { $needElevation | ForEach-Object { $lines.Add("$_ | $Mode | FAILED | the elevated process produced no result") } }
    } catch {
        $needElevation | ForEach-Object { $lines.Add("$_ | $Mode | DECLINED | the administrator prompt was cancelled; nothing was changed") }
    }
}

if ($ResultPath) { [IO.File]::WriteAllLines($ResultPath, $lines, (New-Object Text.UTF8Encoding $false)) }
$lines | ForEach-Object { Write-Output $_ }

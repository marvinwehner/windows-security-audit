#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows security audit collector. Writes findings.json; never changes system state.
.PARAMETER OutputPath
    Absolute path of the findings.json to write. Default: a new session folder
    %USERPROFILE%\WindowsSecurityAudit\<yyyy-MM-dd_HHmmss>\findings.json (the skill's command then needs no
    variables, which Claude Code's PowerShell permission check cannot pre-approve).
.PARAMETER Context
    Mobile = device leaves home (laptop on other networks); Stationary = always on the home network.
.PARAMETER OnlyIds
    Run only these check IDs (used by the fix skill to re-check findings).
.PARAMETER BasePath
    Admin pass: findings.json from the non-elevated pass. Checks marked needsAdmin there are re-run
    elevated and merged; all other results are kept as they are.
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [ValidateSet('Mobile', 'Stationary')] [string] $Context = 'Mobile',
    [string[]] $OnlyIds,
    [string] $BasePath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output "ERROR: PowerShell runs in $($ExecutionContext.SessionState.LanguageMode) mode (e.g. Smart App Control or an application control policy). The audit needs FullLanguage mode and cannot run here."
    exit 2
}

$ToolVersion = '0.1.0'
$SeverityRank = @{ high = 0; medium = 1; low = 2; info = 3 }

# --- check registry --------------------------------------------------------------------------------
$script:Checks = New-Object System.Collections.Generic.List[object]

function Register-Check {
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [scriptblock] $Test,
        [switch] $NeedsAdmin,
        [ValidateSet('auto', 'guided', 'none')] [string] $Fix = 'none'
    )
    $script:Checks.Add([pscustomobject]@{
        Id = $Id; Category = $Category; Title = $Title; Test = $Test; NeedsAdmin = [bool]$NeedsAdmin; Fix = $Fix
    })
}

# Called by check scriptblocks. Status: pass | fail | warn | info | unknown | na
function New-Result {
    param(
        [Parameter(Mandatory)] [ValidateSet('pass', 'fail', 'warn', 'info', 'unknown', 'na')] [string] $Status,
        [ValidateSet('high', 'medium', 'low', 'info')] [string] $Severity = 'info',
        [Parameter(Mandatory)] [string] $Summary,
        [hashtable] $Evidence = @{},
        [switch] $RebootRequired
    )
    [pscustomobject]@{ Status = $Status; Severity = $Severity; Summary = $Summary; Evidence = $Evidence; RebootRequired = [bool]$RebootRequired }
}

# Caps long evidence lists so findings.json stays small enough for Claude to read.
function Limit-List {
    param([object[]] $Items, [int] $Max = 25)
    $all = @($Items)
    [ordered]@{ total = $all.Count; items = @($all | Select-Object -First $Max) }
}

# Registry value or $null if the key or value does not exist (safe under StrictMode).
function Get-RegValue {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Name)
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) { $item.$Name } else { $null }
}

# Severity that depends on whether the device leaves the home network.
function Select-Severity {
    param([Parameter(Mandatory)] [string] $Mobile, [Parameter(Mandatory)] [string] $Stationary)
    if ($Ctx.Mobile) { $Mobile } else { $Stationary }
}

# --- environment -----------------------------------------------------------------------------------
if (-not $OutputPath) {
    $OutputPath = Join-Path $env:USERPROFILE ("WindowsSecurityAudit\{0}\findings.json" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
}

# Admin pass: inherit the first pass's context so severities and numbering stay consistent.
$base = $null
if ($BasePath) {
    $base = [IO.File]::ReadAllText($BasePath) | ConvertFrom-Json
    $Context = $base.meta.context
    $OnlyIds = @($base.checks | Where-Object { $_.status -eq 'needsAdmin' } | ForEach-Object { $_.id })
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem

$lifecycle = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'data\lifecycle.json')) | ConvertFrom-Json
$devTools = @('git', 'node', 'docker', 'code', 'dotnet', 'python', 'java', 'adb' | Where-Object { Get-Command "$_.exe" -ErrorAction SilentlyContinue })
$devMode = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowDevelopmentWithoutDevLicense') -eq 1

$Ctx = [pscustomobject]@{
    Elevated  = $elevated
    Mobile    = ($Context -eq 'Mobile')
    Dev       = ($devMode -or $devTools.Count -ge 2)
    Build     = [int]$cv.CurrentBuild
    Ubr       = [int]$cv.UBR
    Sku       = [int]$os.OperatingSystemSKU
    Lifecycle = $lifecycle
}

Get-ChildItem -Path (Join-Path $PSScriptRoot 'checks') -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }

# --- run -------------------------------------------------------------------------------------------
# An admin pass with nothing to re-check must run no checks, not all of them.
$useFilter = [bool]$base -or $PSBoundParameters.ContainsKey('OnlyIds')
$selected = @($script:Checks | Where-Object { -not $useFilter -or $OnlyIds -contains $_.Id })
$results = @(foreach ($c in $selected) {
    $r = $null
    if ($c.NeedsAdmin -and -not $elevated) {
        $r = [pscustomobject]@{ Status = 'needsAdmin'; Severity = 'info'; Summary = 'Needs administrator rights to check.'; Evidence = @{}; RebootRequired = $false }
    } else {
        try { $r = @(& $c.Test) | Select-Object -Last 1 } catch { $r = New-Result -Status unknown -Summary "Check failed: $($_.Exception.Message)" }
        if (-not $r -or $r.PSObject.Properties.Name -notcontains 'Status') { $r = New-Result -Status unknown -Summary 'Check returned no result.' }
    }
    [ordered]@{
        id = $c.Id; category = $c.Category; title = $c.Title; number = $null
        status = $r.Status; severity = $r.Severity; summary = $r.Summary; evidence = $r.Evidence
        fix = $c.Fix; rebootRequired = $r.RebootRequired; needsAdmin = $c.NeedsAdmin
    }
})

if ($base) {
    $byId = @{}; foreach ($r in $results) { $byId[$r.id] = $r }
    $results = @(foreach ($b in $base.checks) {
        if ($byId.ContainsKey($b.id)) { $byId[$b.id] } else { $b }
    })
}

# Deterministic numbering: actionable findings sorted by severity, then ID.
$n = 0
$actionable = $results | Where-Object { $_.status -in 'fail', 'warn' } |
    Sort-Object @{ Expression = { $SeverityRank[$_.severity] } }, @{ Expression = { $_.id } }
foreach ($r in $actionable) { $n++; $r.number = $n }
foreach ($r in $results) { if ($r.status -notin 'fail', 'warn') { $r.number = $null } }

$meta = [ordered]@{
    toolVersion  = $ToolVersion
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    computer     = $env:COMPUTERNAME
    user         = $identity.Name
    elevated     = $(if ($base) { $true } else { $elevated })
    adminPass    = [bool]$base
    context      = $Context
    build        = "$($cv.CurrentBuild).$($cv.UBR)"
    displayVersion = $cv.DisplayVersion
    sku          = $Ctx.Sku
    edition      = $cv.EditionID
    uiCulture    = (Get-UICulture).Name
    deviceType   = $(if (@(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count) { 'laptop' } else { 'desktop' })
    developer    = $Ctx.Dev
    devTools     = $devTools
    dataAsOf     = $lifecycle.asOf
    dataStale    = ((Get-Date) - [datetime]::ParseExact($lifecycle.asOf, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).TotalDays -gt 180
}
if ($base) { $meta.generatedUtc = $base.meta.generatedUtc; $meta.user = $base.meta.user }

# Compact JSON with one check per line: small for Claude's context, still valid JSON, readable line by line.
$lines = @($results | ForEach-Object { '  ' + ($_ | ConvertTo-Json -Depth 10 -Compress) })
$json = "{`n" + '"meta": ' + ($meta | ConvertTo-Json -Depth 5 -Compress) + ",`n" + '"checks": [' + "`n" + ($lines -join ",`n") + "`n]}`n"
$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[IO.File]::WriteAllText($OutputPath, $json, (New-Object Text.UTF8Encoding $false))

$counts = $results | Group-Object { $_.status } | ForEach-Object { "$($_.Count) $($_.Name)" }
Write-Output "Wrote $($results.Count) checks ($($counts -join ', ')); $n numbered findings -> $OutputPath"

#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the collector and validates its output. When run elevated it also runs the collector with the
    normal (non-elevated) token and checks that admin-only checks are never reported as passed.
    Prints PASS/FAIL per rule; exit code 1 if anything fails.
#>
[CmdletBinding()]
param([string] $OutputDir = (Join-Path $env:TEMP "wsa-test-$(Get-Date -Format yyyyMMdd_HHmmss)"))
$ErrorActionPreference = 'Stop'
$collector = (Resolve-Path (Join-Path $PSScriptRoot '..\scripts\Invoke-SecurityAudit.ps1')).Path
$failures = 0
function Report([string] $Rule, [string[]] $Problems) {
    if ($Problems.Count) { $script:failures++; Write-Output "FAIL  $Rule"; $Problems | ForEach-Object { Write-Output "      $_" } }
    else { Write-Output "PASS  $Rule" }
}
function Read-Findings([string] $Path) { [IO.File]::ReadAllText($Path) | ConvertFrom-Json }

$statuses = 'pass', 'fail', 'warn', 'info', 'unknown', 'needsAdmin', 'na'
$severities = 'high', 'medium', 'low', 'info'
$rank = @{ high = 0; medium = 1; low = 2; info = 3 }

$main = Join-Path $OutputDir 'current\findings.json'
$sw = [Diagnostics.Stopwatch]::StartNew()
& $collector -OutputPath $main -Context Mobile | Out-Null
$seconds = $sw.Elapsed.TotalSeconds
$doc = Read-Findings $main
$checks = @($doc.checks)

Report 'runtime under 60 seconds' @(if ($seconds -ge 60) { "took $([int]$seconds) s" })
Report 'meta fields present' @('toolVersion', 'generatedUtc', 'elevated', 'context', 'build', 'sku', 'dataAsOf', 'dataStale' |
    Where-Object { $doc.meta.PSObject.Properties.Name -notcontains $_ } | ForEach-Object { "missing meta.$_" })
Report 'generatedUtc is ISO 8601' @(if ($doc.meta.generatedUtc -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $doc.meta.generatedUtc })
Report 'check IDs unique' @($checks | Group-Object id | Where-Object Count -gt 1 | ForEach-Object { $_.Name })
Report 'statuses and severities valid' @($checks | Where-Object { $_.status -notin $statuses -or $_.severity -notin $severities } |
    ForEach-Object { "$($_.id): $($_.status)/$($_.severity)" })
Report 'no unknown results (check errors)' @($checks | Where-Object status -eq 'unknown' | ForEach-Object { "$($_.id): $($_.summary)" })

$numbered = @($checks | Where-Object { $_.number } | Sort-Object { [int]$_.number })
Report 'exactly fail/warn findings are numbered' @($checks | Where-Object { ($_.status -in 'fail', 'warn') -xor [bool]$_.number } | ForEach-Object { "$($_.id): status $($_.status), number $($_.number)" })
Report 'numbers are 1..N without gaps' @(for ($i = 0; $i -lt $numbered.Count; $i++) { if ([int]$numbered[$i].number -ne $i + 1) { "expected $($i + 1), got $($numbered[$i].number) ($($numbered[$i].id))" } })
Report 'numbering follows severity' @(for ($i = 1; $i -lt $numbered.Count; $i++) {
    if ($rank[$numbered[$i].severity] -lt $rank[$numbered[$i - 1].severity]) { "$($numbered[$i].id) ($($numbered[$i].severity)) after $($numbered[$i - 1].id) ($($numbered[$i - 1].severity))" }
})

# Same results with German culture (formatting must not depend on the locale).
$de = Join-Path $OutputDir 'de-DE\findings.json'
$job = Start-Job -ScriptBlock {
    param($c, $o)
    [Threading.Thread]::CurrentThread.CurrentCulture = 'de-DE'; [Threading.Thread]::CurrentThread.CurrentUICulture = 'de-DE'
    & $c -OutputPath $o -Context Mobile | Out-Null
} -ArgumentList $collector, $de
$job | Wait-Job -Timeout 120 | Out-Null; Remove-Job $job -Force
$deChecks = @((Read-Findings $de).checks)
Report 'de-DE culture gives the same statuses' @($checks | ForEach-Object {
    $id = $_.id; $other = $deChecks | Where-Object id -eq $id
    if (-not $other -or $other.status -ne $_.status -or $other.number -ne $_.number) { "${id}: $($_.status)/#$($_.number) vs $($other.status)/#$($other.number)" }
})

if ($doc.meta.elevated) {
    $userFindings = & (Join-Path $PSScriptRoot 'Invoke-CollectorUnelevated.ps1') -OutputDir (Join-Path $OutputDir 'unelevated') -Context Mobile
    $userDoc = Read-Findings $userFindings
    Report 'unelevated run is really unelevated' @(if ($userDoc.meta.elevated) { 'meta.elevated is true' })
    Report 'admin-only checks report needsAdmin when unelevated' @(@($userDoc.checks) | Where-Object { $_.needsAdmin -and $_.status -ne 'needsAdmin' } | ForEach-Object { "$($_.id): $($_.status)" })
    Report 'non-admin checks agree between elevated and unelevated runs' @(@($userDoc.checks) | Where-Object { -not $_.needsAdmin } | ForEach-Object {
        $id = $_.id; $e = $checks | Where-Object id -eq $id
        if ($e.status -ne $_.status) { "${id}: unelevated $($_.status) vs elevated $($e.status)" }
    })
} else {
    Write-Output 'SKIP  elevated/unelevated comparison (run this test from an elevated session to include it)'
}

Write-Output ''
Write-Output "Output: $OutputDir"
Write-Output $(if ($failures) { "$failures rule(s) failed." } else { 'All collector tests passed.' })
exit [int]($failures -gt 0)

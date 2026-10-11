#Requires -Version 5.1
<#
.SYNOPSIS
    Static checks for the repository. Prints PASS/FAIL per rule; exit code 1 if anything fails.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = 0
function Report([string] $Rule, [string[]] $Problems) {
    if ($Problems.Count) { $script:failures++; Write-Output "FAIL  $Rule"; $Problems | ForEach-Object { Write-Output "      $_" } }
    else { Write-Output "PASS  $Rule" }
}

$ps1 = @(Get-ChildItem (Join-Path $repo 'scripts'), (Join-Path $repo 'tests') -Recurse -Filter '*.ps1')

# Windows PowerShell 5.1 reads BOM-less scripts as ANSI, so any non-ASCII character would be garbled.
Report 'scripts are ASCII-only' @($ps1 | ForEach-Object {
    $bytes = [IO.File]::ReadAllBytes($_.FullName); $i = [Array]::FindIndex($bytes, [Predicate[byte]] { param($b) $b -gt 127 })
    if ($i -ge 0) { "$($_.Name): non-ASCII byte at offset $i" }
})

Report 'scripts parse without errors' @($ps1 | ForEach-Object {
    $errs = $null; [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs) | Out-Null
    foreach ($e in @($errs)) { if ($e) { "$($_.Name):$($e.Extent.StartLineNumber) $($e.Message)" } }
})

# Detection must not parse localized output, and nothing may look like attacker tooling to AMSI/Defender.
$banned = [ordered]@{
    'DisplayName/DisplayGroup (localized)' = '\.Display(Name|Group)\b'
    'event .Message (localized)'           = '(?<!Exception)\.Message\b'
    'net accounts / whoami (localized)'    = '\bnet(\.exe)?\s+accounts\b|\bwhoami\b'
    'netsh ... show (localized)'           = '\bnetsh\b.*\bshow\b'
    'manage-bde / tpmtool / powercfg /q'   = '\bmanage-bde\b|\btpmtool\b|\bpowercfg\b.*\s/q'
    'Add-Type / encoded commands / iex'    = '\bAdd-Type\b|EncodedCommand|FromBase64String|\bInvoke-Expression\b|\biex\b'
    'Win32_Product (slow, triggers repairs)' = '\bWin32_Product\b'
    'requests to test/malicious domains'   = 'smartscreentestratings|Invoke-WebRequest|\bcurl(\.exe)?\b|DownloadString'
}
foreach ($name in $banned.Keys) {
    Report "no $name" @(Get-ChildItem (Join-Path $repo 'scripts') -Recurse -Filter '*.ps1' | ForEach-Object {
        $file = $_
        Select-String -Path $file.FullName -Pattern $banned[$name] | Where-Object { $_.Line.TrimStart() -notmatch '^#' } |
            ForEach-Object { "$($file.Name):$($_.LineNumber): $($_.Line.Trim())" }
    })
}

# Every check is documented, and fix flags match the fix definitions.
$checks = @(Get-ChildItem (Join-Path $repo 'scripts\checks') -Filter '*.ps1' | Select-String -Pattern "Register-Check\s+-Id\s+'([^']+)'\s+-Category\s+'([^']+)'.*?(-Fix\s+(\w+))?\s+-Test" |
    ForEach-Object { [pscustomobject]@{ Id = $_.Matches[0].Groups[1].Value; Category = $_.Matches[0].Groups[2].Value; Fix = $(if ($_.Line -match '-Fix\s+(\w+)') { $Matches[1] } else { 'none' }) } })
$fixes = @(Get-ChildItem (Join-Path $repo 'scripts\fixes') -Filter '*.ps1' | Select-String -Pattern "Register-Fix\s+-Id\s+'([^']+)'" | ForEach-Object { $_.Matches[0].Groups[1].Value })

$registrations = @(Get-ChildItem (Join-Path $repo 'scripts\checks') -Filter '*.ps1' | Select-String -Pattern '^\s*Register-Check\b').Count
Report "all $registrations check registrations parsed" @(if ($registrations -eq 0 -or $checks.Count -ne $registrations) { "parsed $($checks.Count) of $registrations Register-Check calls" })
Report 'check IDs are unique' @($checks | Group-Object Id | Where-Object Count -gt 1 | ForEach-Object { "duplicate $($_.Name)" })
Report 'every check has a reference section' @($checks | ForEach-Object {
    $ref = Join-Path $repo "references\checks\$($_.Category).md"
    if (-not (Test-Path $ref)) { "$($_.Id): missing $ref" }
    elseif (-not (Select-String -Path $ref -Pattern "^## $([regex]::Escape($_.Id)) " -Quiet)) { "$($_.Id): no '## $($_.Id)' section in $($_.Category).md" }
})
Report 'fix = auto exactly for checks with a fix definition' @(
    @($checks | Where-Object { $_.Fix -eq 'auto' -and $fixes -notcontains $_.Id } | ForEach-Object { "$($_.Id): marked auto but no Register-Fix" }) +
    @($fixes | Where-Object { $id = $_; -not ($checks | Where-Object { $_.Id -eq $id -and $_.Fix -eq 'auto' }) } | ForEach-Object { "${_}: Register-Fix but check not marked auto" })
)

$plugin = Get-Content (Join-Path $repo '.claude-plugin\plugin.json') -Raw | ConvertFrom-Json
$collectorVersion = if ((Get-Content (Join-Path $repo 'scripts\Invoke-SecurityAudit.ps1') -Raw) -match "\`$ToolVersion = '([^']+)'") { $Matches[1] } else { '?' }
Report 'plugin.json version matches collector version' @(if ($plugin.version -ne $collectorVersion) { "plugin.json $($plugin.version) vs collector $collectorVersion" })

Write-Output ''
Write-Output $(if ($failures) { "$failures rule(s) failed." } else { 'All static rules passed.' })
exit [int]($failures -gt 0)

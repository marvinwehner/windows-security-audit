# Microsoft Defender checks. Dot-sourced by Invoke-SecurityAudit.ps1.

# Defender settings only matter when Defender is the active antivirus. Returns $null when another product
# is in charge (Defender passive or disabled), so those checks report "na" instead of false failures.
function Get-ActiveDefenderStatus {
    try { $s = Get-MpComputerStatus -ErrorAction Stop } catch { return $null }
    if ($s.AMRunningMode -ne 'Normal' -or -not $s.AntivirusEnabled) { return $null }
    $s
}

function New-DefenderInactiveResult {
    New-Result -Status na -Summary 'Microsoft Defender is not the active antivirus on this PC, so its settings do not apply.'
}

Register-Check -Id 'DEF-06' -Category 'defender' -Title 'Blocking of potentially unwanted apps (PUA)' -Fix auto -Test {
    if (-not (Get-ActiveDefenderStatus)) { return New-DefenderInactiveResult }
    $v = [int](Get-MpPreference).PUAProtection
    $evidence = @{ puaProtection = $v }
    $sev = if ($Ctx.Dev) { 'low' } else { 'medium' }
    switch ($v) {
        1 { New-Result -Status pass -Summary 'Defender blocks potentially unwanted apps (adware, bundled junk, crypto miners).' -Evidence $evidence }
        2 { New-Result -Status warn -Severity $sev -Summary 'Defender only logs potentially unwanted apps (audit mode) instead of blocking them.' -Evidence $evidence }
        default { New-Result -Status fail -Severity $sev -Summary 'Defender does not block potentially unwanted apps (adware, bundled junk, crypto miners).' -Evidence $evidence }
    }
}

Register-Check -Id 'DEF-09' -Category 'defender' -Title 'Network protection' -Fix guided -Test {
    if (-not (Get-ActiveDefenderStatus)) { return New-DefenderInactiveResult }
    $v = [int](Get-MpPreference).EnableNetworkProtection
    $evidence = @{ enableNetworkProtection = $v }
    $sev = if ($Ctx.Dev) { 'low' } else { 'medium' }
    switch ($v) {
        1 { New-Result -Status pass -Summary 'Network protection blocks connections to known malicious and phishing sites in all apps.' -Evidence $evidence }
        2 { New-Result -Status warn -Severity $sev -Summary 'Network protection only logs connections to malicious sites (audit mode) instead of blocking them.' -Evidence $evidence }
        default { New-Result -Status fail -Severity $sev -Summary 'Network protection is off: apps other than Microsoft Edge can connect to known malicious and phishing sites.' -Evidence $evidence }
    }
}

Register-Check -Id 'DEF-12' -Category 'defender' -Title 'Defender exclusions' -NeedsAdmin -Fix guided -Test {
    if (-not (Get-ActiveDefenderStatus)) { return New-DefenderInactiveResult }
    $p = Get-MpPreference
    $paths = @($p.ExclusionPath | Where-Object { $_ })
    $procs = @($p.ExclusionProcess | Where-Object { $_ })
    $exts = @($p.ExclusionExtension | Where-Object { $_ })
    $evidence = @{ paths = (Limit-List $paths); processes = (Limit-List $procs); extensions = (Limit-List $exts) }
    $total = $paths.Count + $procs.Count + $exts.Count
    if ($total -eq 0) {
        return New-Result -Status pass -Summary 'No Defender exclusions.' -Evidence $evidence
    }
    # Broad exclusions that malware can hide in.
    $profileRoot = $env:USERPROFILE.TrimEnd('\')
    $risky = @($paths | Where-Object {
        $p2 = $_.TrimEnd('\')
        $p2 -match '^[A-Za-z]:$' -or $p2 -eq $profileRoot -or $p2 -match '\\(Downloads|Desktop|Temp|AppData)$'
    }) + @($procs | Where-Object { $_ -match '(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$' }) +
        @($exts | Where-Object { $_ -match '(?i)^\.?(exe|dll|ps1|bat|cmd|js|vbs|scr)$' })
    if ($risky.Count) {
        $evidence.risky = $risky
        New-Result -Status fail -Severity high -Summary "$($risky.Count) broad Defender exclusion(s) where malware would not be scanned." -Evidence $evidence
    } else {
        New-Result -Status info -Summary "$total Defender exclusion(s); none look dangerous, but nothing in them is scanned." -Evidence $evidence
    }
}

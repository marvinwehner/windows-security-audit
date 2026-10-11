# Microsoft Defender checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'DEF-12' -Category 'defender' -Title 'Defender exclusions' -NeedsAdmin -Fix guided -Test {
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

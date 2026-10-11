# Windows version and update checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'OS-01' -Category 'os' -Title 'Windows version still supported' -Fix guided -Test {
    $entry = $Ctx.Lifecycle.windows.PSObject.Properties[[string]$Ctx.Build]
    if (-not $entry) {
        return New-Result -Status unknown -Summary "Windows build $($Ctx.Build) is not in this tool's support table; check support dates manually." -Evidence @{ build = $Ctx.Build }
    }
    $isEnterprise = @($Ctx.Lifecycle.enterpriseSkus) -contains $Ctx.Sku
    $endText = if ($isEnterprise) { $entry.Value.enterpriseEnd } else { $entry.Value.homeProEnd }
    $end = [datetime]::ParseExact($endText, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $daysLeft = [int][math]::Floor(($end - (Get-Date).Date).TotalDays)
    $evidence = @{ release = $entry.Value.release; build = $Ctx.Build; supportEnds = $endText; daysLeft = $daysLeft; enterpriseServicing = $isEnterprise }
    if ($daysLeft -lt 0) {
        New-Result -Status fail -Severity high -Summary "Windows 11 $($entry.Value.release) stopped receiving security updates on $endText." -Evidence $evidence
    } elseif ($daysLeft -lt 60) {
        New-Result -Status warn -Severity medium -Summary "Windows 11 $($entry.Value.release) stops receiving security updates on $endText ($daysLeft days left)." -Evidence $evidence
    } else {
        New-Result -Status pass -Summary "Windows 11 $($entry.Value.release) is supported until $endText." -Evidence $evidence
    }
}

Register-Check -Id 'OS-02' -Category 'os' -Title 'Latest security update installed' -Fix guided -Test {
    # Cumulative updates are CBS packages named Package_for_RollupFix~...~~<base build>.<UBR>.x.y. The base build
    # can differ from CurrentBuild (25H2 is serviced on the 24H2 branch), so match the UBR only.
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    $packages = @(Get-ChildItem $root -Name | Where-Object { $_ -like 'Package_for_RollupFix~*' } | ForEach-Object {
        if ($_ -match '~~\d+\.(\d+)\.') {
            $p = Get-ItemProperty (Join-Path $root $_)
            $ft = ([int64][uint32]$p.InstallTimeHigh -shl 32) -bor [int64][uint32]$p.InstallTimeLow
            [pscustomobject]@{ Ubr = [int]$Matches[1]; Installed = $(if ($ft) { [DateTime]::FromFileTimeUtc($ft) } else { $null }) }
        }
    })
    $current = $packages | Where-Object { $_.Ubr -eq $Ctx.Ubr -and $_.Installed } | Sort-Object Installed -Descending | Select-Object -First 1
    if (-not $current) {
        return New-Result -Status unknown -Summary 'Could not determine when the last cumulative update was installed.' -Evidence @{ ubr = $Ctx.Ubr; packagesFound = $packages.Count }
    }
    $age = [int][math]::Floor(((Get-Date).ToUniversalTime() - $current.Installed).TotalDays)
    $evidence = @{ ubr = $Ctx.Ubr; installedUtc = $current.Installed.ToString('yyyy-MM-dd'); daysAgo = $age }
    if ($age -gt 70) {
        New-Result -Status fail -Severity high -Summary "The last Windows security update was installed $age days ago; at least two monthly updates are probably missing." -Evidence $evidence
    } elseif ($age -gt 40) {
        New-Result -Status warn -Severity medium -Summary "The last Windows security update was installed $age days ago; this month's update is probably missing." -Evidence $evidence
    } else {
        New-Result -Status pass -Summary "The last Windows security update was installed $age days ago." -Evidence $evidence
    }
}

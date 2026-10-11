# Network and firewall checks. Dot-sourced by Invoke-SecurityAudit.ps1.

# Firewall rules via the HNetCfg COM API: works without admin (Get-NetFirewallPortFilter -All is denied for
# standard users) and is fast. Uses only numeric enums and raw paths/group IDs; the rule name is shown as
# evidence but never parsed. Rule IDs are not exposed here; the fix engine looks them up by program path.
$script:FirewallInventory = $null
function Get-FirewallInventory {
    if ($script:FirewallInventory) { return $script:FirewallInventory }
    $windir = $env:windir.TrimEnd('\') + '\'
    $script:FirewallInventory = @(@((New-Object -ComObject HNetCfg.FwPolicy2).Rules) | ForEach-Object {
        $program = [Environment]::ExpandEnvironmentVariables([string]$_.ApplicationName)
        $group = [string]$_.Grouping
        $isApp = $program -and $program -ne 'System' -and -not $program.StartsWith($windir, [StringComparison]::OrdinalIgnoreCase)
        [pscustomobject]@{
            Name       = [string]$_.Name
            Inbound    = ($_.Direction -eq 1)              # NET_FW_RULE_DIR_IN
            Allow      = ($_.Action -eq 1)                 # NET_FW_ACTION_ALLOW
            Enabled    = [bool]$_.Enabled
            Public     = (($_.Profiles -band 4) -ne 0)     # NET_FW_PROFILE2_PUBLIC
            Profiles   = [int]$_.Profiles
            AnyPort    = ([string]$_.LocalPorts -in '*', '')
            Program    = $program
            # Third-party app rule: a program outside Windows and not in a built-in (@resource) rule group.
            ThirdParty = $isApp -and -not $group.StartsWith('@')
        }
    })
    $script:FirewallInventory
}

Register-Check -Id 'NET-04' -Category 'network' -Title 'Apps allowed through the firewall on public networks' -Fix guided -Test {
    $rules = @(Get-FirewallInventory | Where-Object {
        $_.ThirdParty -and $_.Enabled -and $_.Inbound -and $_.Allow -and $_.Public -and $_.AnyPort -and (Test-Path -LiteralPath $_.Program)
    })
    $apps = @($rules | Group-Object Program | ForEach-Object {
        [ordered]@{ program = $_.Name; name = $_.Group[0].Name; alsoPrivate = (($_.Group[0].Profiles -band 2) -ne 0); rules = $_.Count }
    })
    $category = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.NetworkCategory })
    $evidence = @{ apps = (Limit-List $apps 40); currentNetworkCategories = $category }
    if ($apps.Count -eq 0) {
        return New-Result -Status pass -Summary 'No apps accept connections on every port from public networks.' -Evidence $evidence
    }
    $sev = Select-Severity -Mobile medium -Stationary low
    New-Result -Status warn -Severity $sev -Summary "$($apps.Count) app(s) accept incoming connections on any port from public networks (other devices on the same network can reach them)." -Evidence $evidence
}

Register-Check -Id 'NET-05' -Category 'network' -Title 'Firewall rules for programs that no longer exist' -Fix guided -Test {
    $stale = @(Get-FirewallInventory | Where-Object { $_.ThirdParty -and -not (Test-Path -LiteralPath $_.Program) })
    $programs = @($stale | Group-Object Program | ForEach-Object {
        [ordered]@{ program = $_.Name; rules = $_.Count; enabledAllow = @($_.Group | Where-Object { $_.Enabled -and $_.Allow }).Count }
    })
    $evidence = @{ programs = (Limit-List $programs 40); ruleCount = $stale.Count }
    if ($stale.Count -eq 0) {
        return New-Result -Status pass -Summary 'No firewall rules point to programs that no longer exist.' -Evidence $evidence
    }
    New-Result -Status warn -Severity low -Summary "$($stale.Count) firewall rule(s) still allow programs that are no longer installed; a file placed at one of those paths would be let through." -Evidence $evidence
}

Register-Check -Id 'NET-16' -Category 'network' -Title 'LLMNR name resolution' -Fix auto -Test {
    $value = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $listening = @(Get-NetUDPEndpoint -LocalPort 5355 -ErrorAction SilentlyContinue).Count -gt 0
    $evidence = @{ enableMulticastPolicy = $value; udp5355Listening = $listening }
    if ($value -eq 0) {
        if ($listening) {
            New-Result -Status pass -Summary 'LLMNR is disabled by policy; port 5355 closes after the next restart.' -Evidence $evidence -RebootRequired
        } else {
            New-Result -Status pass -Summary 'LLMNR is disabled.' -Evidence $evidence
        }
    } else {
        $sev = Select-Severity -Mobile medium -Stationary low
        New-Result -Status fail -Severity $sev -Summary 'LLMNR is enabled; on untrusted networks an attacker can answer name lookups and capture login hashes.' -Evidence $evidence
    }
}

Register-Check -Id 'NET-17' -Category 'network' -Title 'NetBIOS over TCP/IP' -Fix guided -Test {
    $adapters = @{}
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { $adapters[('Tcpip_' + $_.InterfaceGuid).ToLowerInvariant()] = $_ }
    # Virtual adapters (WSL/Hyper-V vEthernet, Wi-Fi Direct) are recreated with NetBIOS on (default 0)
    # but only reach local VMs or paired devices, so they are reported separately as info.
    $enabled = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
        $a = $adapters[$_.PSChildName.ToLowerInvariant()]
        $opt = Get-RegValue $_.PSPath 'NetbiosOptions'
        if ($a -and $opt -ne 2) { [ordered]@{ adapter = $a.InterfaceDescription; physical = [bool]$a.HardwareInterface; netbiosOptions = $opt } }
    })
    $physical = @($enabled | Where-Object { $_.physical })
    $evidence = @{ adaptersWithNetbios = $enabled }
    if ($physical.Count) {
        $sev = Select-Severity -Mobile medium -Stationary low
        New-Result -Status fail -Severity $sev -Summary "NetBIOS over TCP/IP is on for $($physical.Count) network adapter(s); like LLMNR it can be abused on untrusted networks to capture login hashes." -Evidence $evidence
    } elseif ($enabled.Count) {
        New-Result -Status info -Summary "NetBIOS is off on all physical network adapters; it is still on for $($enabled.Count) virtual adapter(s) (e.g. WSL/Hyper-V), which only local virtual machines can reach." -Evidence $evidence
    } else {
        New-Result -Status pass -Summary 'NetBIOS over TCP/IP is turned off on all network adapters.' -Evidence $evidence
    }
}

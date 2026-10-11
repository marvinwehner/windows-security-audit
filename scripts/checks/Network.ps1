# Network checks. Dot-sourced by Invoke-SecurityAudit.ps1; uses Register-Check / New-Result / $Ctx.

Register-Check -Id 'NET-16' -Category 'network' -Title 'LLMNR name resolution' -Fix auto -Test {
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $value = if ($policy -and ($policy.PSObject.Properties.Name -contains 'EnableMulticast')) { [int]$policy.EnableMulticast } else { $null }
    $listening = @(Get-NetUDPEndpoint -LocalPort 5355 -ErrorAction SilentlyContinue).Count -gt 0
    $evidence = @{ enableMulticastPolicy = $value; udp5355Listening = $listening }
    if ($value -eq 0) {
        if ($listening) {
            New-Result -Status pass -Summary 'LLMNR is disabled by policy; port 5355 closes after the next restart.' -Evidence $evidence -RebootRequired
        } else {
            New-Result -Status pass -Summary 'LLMNR is disabled.' -Evidence $evidence
        }
    } else {
        $sev = if ($Ctx.Mobile) { 'medium' } else { 'low' }
        New-Result -Status fail -Severity $sev -Summary 'LLMNR is enabled; on untrusted networks an attacker can answer name lookups and capture login hashes.' -Evidence $evidence
    }
}

# Network fixes. Dot-sourced by Invoke-SecurityFix.ps1; uses Register-Fix / Get-RegValue / Set-RegValueState.

$llmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'

Register-Fix -Id 'NET-16' -Scope machine -MayNeedRestart `
    -Describe { param($s) "set policy $llmnrKey\EnableMulticast = 0 (turns off LLMNR)" } `
    -GetState { @{ EnableMulticast = (Get-RegValue $llmnrKey 'EnableMulticast') } } `
    -Apply { Set-RegValueState $llmnrKey 'EnableMulticast' 0 } `
    -Restore { param($prior) Set-RegValueState $llmnrKey 'EnableMulticast' $prior.EnableMulticast }

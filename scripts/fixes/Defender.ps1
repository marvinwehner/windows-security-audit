# Microsoft Defender fixes. Dot-sourced by Invoke-SecurityFix.ps1.

# Get-MpPreference returns numbers; Set-MpPreference takes these names.
$mpModeNames = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode' }

Register-Fix -Id 'DEF-06' -Scope machine `
    -Describe { param($s) 'set Defender PUAProtection = Enabled (block potentially unwanted apps)' } `
    -GetState { @{ PUAProtection = [int](Get-MpPreference).PUAProtection } } `
    -Apply { Set-MpPreference -PUAProtection Enabled } `
    -Restore { param($prior) Set-MpPreference -PUAProtection $mpModeNames[[int]$prior.PUAProtection] }

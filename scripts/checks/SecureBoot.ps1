# Secure Boot certificate transition (2011 -> 2023 CAs). Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'SB-02' -Category 'secureboot' -Title 'Secure Boot 2023 certificate update' -Fix guided -Test {
    $enabled = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    if ($enabled -ne 1) {
        return New-Result -Status na -Summary 'Secure Boot is off, so its certificate update does not apply.' -Evidence @{ secureBootEnabled = $enabled }
    }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
    $status = Get-RegValue $key 'UEFICA2023Status'
    $err = Get-RegValue $key 'UEFICA2023Error'
    $evidence = @{ status = $status; error = $err; capable = (Get-RegValue $key 'WindowsUEFICA2023Capable') }
    if ($status -eq 'Updated' -and -not $err) {
        New-Result -Status pass -Summary 'The new 2023 Secure Boot certificates are installed.' -Evidence $evidence
    } elseif ($status -eq 'InProgress' -and -not $err) {
        New-Result -Status warn -Severity medium -Summary 'The Secure Boot certificate update is in progress; it usually needs one or two restarts to finish.' -Evidence $evidence -RebootRequired
    } elseif ($err) {
        New-Result -Status fail -Severity medium -Summary "The Secure Boot certificate update failed (error $err); a firmware (BIOS/UEFI) update from the PC maker is usually needed." -Evidence $evidence
    } else {
        New-Result -Status fail -Severity medium -Summary 'The Secure Boot certificate update has not started; the old 2011 certificates expire in 2026.' -Evidence $evidence
    }
}

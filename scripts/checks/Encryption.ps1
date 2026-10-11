# Drive encryption checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'ENC-01' -Category 'encryption' -Title 'System drive encrypted and protected' -NeedsAdmin -Fix guided -Test {
    $drive = $env:SystemDrive
    $vol = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction SilentlyContinue
    if (-not $vol) {
        return New-Result -Status na -Summary 'BitLocker / device encryption is not available on this device.' -Evidence @{ drive = $drive }
    }
    $ids = @((Invoke-CimMethod -InputObject $vol -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID)
    $types = @($ids | Where-Object { $_ } | ForEach-Object {
        [int](Invoke-CimMethod -InputObject $vol -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $_ }).KeyProtectorType
    })
    # KeyProtectorType: 1 TPM, 3 numerical password (recovery key), 4 TPM+PIN, 5 TPM+startup key, 6 TPM+PIN+key, 8 passphrase
    $hasTpm = @($types | Where-Object { $_ -in 1, 4, 5, 6 }).Count -gt 0
    $hasRecovery = $types -contains 3
    $evidence = @{ drive = $drive; conversionStatus = $vol.ConversionStatus; protectionStatus = $vol.ProtectionStatus; protectorTypes = $types; encryptionMethod = $vol.EncryptionMethod }
    $sev = Select-Severity -Mobile high -Stationary low
    if ($vol.ConversionStatus -eq 0) {
        New-Result -Status fail -Severity $sev -Summary "Drive $drive is not encrypted; anyone with the device can read its files." -Evidence $evidence
    } elseif ($vol.ProtectionStatus -ne 1 -and -not $hasTpm) {
        New-Result -Status fail -Severity $sev -Summary "Drive $drive is encrypted, but the key is stored unprotected on the drive (device encryption was never activated), so the encryption does not protect the data." -Evidence $evidence
    } elseif ($vol.ProtectionStatus -ne 1) {
        New-Result -Status warn -Severity medium -Summary "Encryption on drive $drive is suspended." -Evidence $evidence
    } elseif (-not $hasRecovery) {
        New-Result -Status warn -Severity medium -Summary "Drive $drive is protected but has no recovery key; a hardware or firmware change could lock you out of your data." -Evidence $evidence
    } else {
        New-Result -Status pass -Summary "Drive $drive is encrypted and protected. Make sure the recovery key is saved somewhere outside this PC." -Evidence $evidence
    }
}

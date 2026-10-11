# Legacy feature and attack-surface checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'LEG-06' -Category 'legacy' -Title 'File extensions visible' -Fix guided -Test {
    $hide = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt'
    if ($null -eq $hide) { $hide = 1 }   # Windows default: hidden
    if ($hide -eq 0) {
        New-Result -Status pass -Summary 'File extensions are shown in Explorer.' -Evidence @{ hideFileExt = $hide }
    } else {
        $sev = if ($Ctx.Dev) { 'low' } else { 'medium' }
        New-Result -Status fail -Severity $sev -Summary 'File extensions are hidden, so a file named "invoice.pdf.exe" shows up as "invoice.pdf".' -Evidence @{ hideFileExt = $hide }
    }
}

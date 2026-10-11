# Legacy feature and attack-surface checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'LEG-06' -Category 'legacy' -Title 'File extensions visible' -Fix auto -Test {
    $adv = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ErrorAction SilentlyContinue
    $hide = if ($adv -and ($adv.PSObject.Properties.Name -contains 'HideFileExt')) { [int]$adv.HideFileExt } else { 1 }
    if ($hide -eq 0) {
        New-Result -Status pass -Summary 'File extensions are shown in Explorer.' -Evidence @{ hideFileExt = $hide }
    } else {
        New-Result -Status fail -Severity medium -Summary 'File extensions are hidden, so "invoice.pdf.exe" looks like "invoice.pdf".' -Evidence @{ hideFileExt = $hide }
    }
}

# Account and sign-in checks. Dot-sourced by Invoke-SecurityAudit.ps1.

Register-Check -Id 'ACC-01' -Category 'accounts' -Title 'Everyday account is not an administrator' -Fix guided -Test {
    # Non-elevated admins carry Administrators (S-1-5-32-544) as a deny-only SID, which IsInRole() ignores.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $denyOnly = @($id.Claims | Where-Object { $_.Type -eq [Security.Claims.ClaimTypes]::DenyOnlySid -and $_.Value -eq 'S-1-5-32-544' }).Count -gt 0
    $isAdmin = $Ctx.Elevated -or $denyOnly
    $members = @()
    try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }
    $evidence = @{ user = $id.Name; isAdministrator = $isAdmin; administrators = $members }
    if ($isAdmin) {
        $sev = if ($Ctx.Dev) { 'low' } else { 'medium' }
        New-Result -Status warn -Severity $sev -Summary "Your everyday account ($($id.Name)) is an administrator, so malware you run accidentally is one click on a permission prompt away from full control." -Evidence $evidence
    } else {
        New-Result -Status pass -Summary "Your everyday account ($($id.Name)) is a standard user." -Evidence $evidence
    }
}

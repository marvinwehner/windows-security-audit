# Microsoft Defender

All Defender checks are "not applicable" when another antivirus product is active.

## DEF-06 · Blocking of potentially unwanted apps (PUA)
**What it is:** Defender can block "potentially unwanted apps": adware, browser hijackers, bundled installers,
crypto miners and fake "PC optimizers". On many PCs Defender's default is audit mode, which only logs them.
**Why it matters:** These apps are a common way to get unwanted software, ads and data collection onto a PC.
**Recommendation:** Turn blocking on.
**If you change it:** Defender quarantines such apps, including some free tools that bundle extra offers and
some torrent or mining tools. A blocked app can be restored under Windows Security > Protection history.
**Fix:** automatic: sets `PUAProtection = Enabled` (needs one administrator prompt). Restart: no.
**Undo:** automatic (restores the previous mode).
**Learn more:** https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus

## DEF-09 · Network protection
**What it is:** Network protection blocks connections to known malicious, phishing and scam websites in every
app (other browsers, chat apps, scripts), not only in Microsoft Edge. It also works on Windows 11 Home.
**Why it matters:** Browsers other than Edge do not use Microsoft's malicious-site list.
**Recommendation:** Turn it on.
**If you change it:** Blocked connections show a notification that may say "blocked by your IT
administrator". Very rarely a legitimate site is blocked; audit mode is the fallback.
**Fix:** guided.
1. Open PowerShell as administrator and run: `Set-MpPreference -EnableNetworkProtection Enabled`
2. Check: `(Get-MpPreference).EnableNetworkProtection` shows `1`. It takes about 20 seconds to become active.
3. Optional test: open https://smartscreentestratings2.net in Chrome, Firefox or Brave (not Edge, not
   PowerShell). The page should be blocked with a Windows Security notification.
**Never** test it by requesting that address from PowerShell or a script: Defender then reports a "Severe"
threat (Behavior:Win32/PShellMal.A) and terminates the PowerShell process.
**Undo:** `Set-MpPreference -EnableNetworkProtection Disabled` (as administrator).
**Learn more:** https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection

## DEF-12 · Defender exclusions
**What it is:** Exclusions are folders, files, programs or file types that Defender does not scan.
**Why it matters:** Malware placed in an excluded location is never detected. Malware also adds exclusions
itself to hide. Developer tools often recommend exclusions for build folders to speed up builds; those are
acceptable if narrow.
**Recommendation:** Remove broad exclusions (whole drives, the user folder, Downloads, Temp, script engines
such as powershell.exe, executable file types). Keep narrow build-cache exclusions only if you need them.
**If you change it:** Scans and builds in those folders get slower.
**Fix:** guided.
1. Windows Security > Virus & threat protection > Manage settings > Exclusions > Add or remove exclusions.
2. Remove the exclusions listed in the finding that you don't recognise or don't need.
**Undo:** add the exclusion again in the same place.
**Learn more:** https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference

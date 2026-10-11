# Secure Boot

## SB-02 · Secure Boot 2023 certificate update
**What it is:** Secure Boot checks that only trusted software starts before Windows. It relies on Microsoft
certificates from 2011 that expire in 2026 (the last one, used for the Windows boot manager, on 2026-10-19).
Windows replaces them with 2023 certificates through Windows Update, written into the PC's firmware.
**Why it matters:** The PC keeps booting without the update, but it can no longer receive fixes for
boot-level security holes (malware that loads before Windows, so-called bootkits).
**Recommendation:** Install all Windows updates and restart twice. If the update fails, install the latest
firmware (BIOS/UEFI) update from the PC maker.
**If you change it:** Normal updates and restarts. A firmware update can reset firmware settings and, on
encrypted drives, ask for the BitLocker recovery key once: have the recovery key ready first.
Writing new certificates into the firmware cannot be undone (this is intended).
**Fix:** guided (one-way change made by Windows Update; never forced by this tool).
1. Settings > Windows Update > install all updates, restart, and restart once more.
2. Check Windows Security > Device security > Secure Boot for the status.
3. If it still fails: download the latest BIOS/UEFI update from the PC maker's support page (search for the
   model name). Save your BitLocker recovery key first (see ENC-01) and keep the laptop on power.
**Undo:** not possible and not needed.
**Learn more:** https://support.microsoft.com/help/5062710

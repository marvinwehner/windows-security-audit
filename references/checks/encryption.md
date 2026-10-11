# Drive encryption

## ENC-01 · System drive encrypted and protected
**What it is:** Drive encryption (BitLocker on Pro, "Device encryption" on Home) makes the files unreadable
without signing in to this PC. On many Home PCs Windows encrypts the drive automatically but only *activates*
the protection after someone signs in with a Microsoft account; until then the key lies unprotected on the
drive ("waiting for activation"), which protects nothing.
**Why it matters:** If the device is lost or stolen, anyone can remove the drive (or boot another system) and
read all files, saved browser sessions and passwords.
**Recommendation:** Laptops that leave home: turn protection on and save the recovery key. A desktop that
never leaves home has a lower risk (burglary), so this can be a conscious decision not to.
**If you change it:** Protection is invisible in daily use. But after firmware (BIOS) updates, hardware or
Secure Boot changes, Windows may ask for the 48-digit **recovery key**; without it the data is lost. Save
the key outside this PC (Microsoft account, printout, password manager).
**Fix:** guided.
- Windows 11 Home: Settings > Privacy & security > Device encryption. If it says protection is waiting,
  sign in once with a Microsoft account (Settings > Accounts > Your info): Windows then activates the
  protection and stores the recovery key in that account (check at https://aka.ms/myrecoverykey).
  If you switch back to a local account afterwards, check the Device encryption page again to confirm
  that protection is still on.
- Windows 11 Pro: Settings > Privacy & security > Device encryption, or Control Panel > BitLocker Drive
  Encryption > Turn on BitLocker; save the recovery key when asked.
**Undo:** Settings > Privacy & security > Device encryption > Off (decrypts the drive, takes a while).
**Learn more:** https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/ ·
recovery key: https://support.microsoft.com/en-us/windows/find-your-bitlocker-recovery-key-6b71ad27-0b89-ea08-f143-056f5ab347d6

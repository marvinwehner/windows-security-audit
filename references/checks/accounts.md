# Accounts and sign-in

## ACC-01 · Everyday account is not an administrator
**What it is:** Administrator accounts can change everything on the PC after one click on the "Do you want to
allow this app to make changes?" prompt (UAC). Standard accounts need an administrator's password for that.
**Why it matters:** Malware you start by accident usually needs that one click. People click "Yes" out of
habit; typing a separate password makes them stop and think.
**Recommendation:** Create a separate administrator account, then make your everyday account a standard user.
On developer machines that constantly install tools this is often impractical; then at least set UAC to
"Always notify".
**If you change it:** Installing programs and changing system settings asks for the admin account's password.
Some installers that only install "for me" keep working without it.
**Fix:** guided. Do the steps in this order, so you can never lock yourself out:
1. Settings > Accounts > Other users > Add account: create a new local account (e.g. "Admin") with a strong
   password you will not forget.
2. Select the new account > Change account type > Administrator.
3. Sign out and sign in to the new admin account to test that its password works.
4. Still signed in as the new admin: Settings > Accounts > Other users > select your everyday account >
   Change account type > Standard User. Then sign out and back in to your everyday account.
**Undo:** from the admin account, change your everyday account back to Administrator.
**Learn more:** https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/

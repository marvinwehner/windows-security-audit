# Fixing findings safely

Follow these steps for every change. Change nothing the user has not confirmed in step 5. Use only the
commands below, with the literal plugin and session paths (no `$env:` variables).

`<plugin>` = the plugin root given in the skill, `<session>` = the audit session folder (contains findings.json).

1. **Map numbers to IDs** using the `number` field in `<session>\findings.json`. Say so if a number does not
   exist or the finding has status pass/info (nothing to fix).
2. **Split** into automatic (`fix` = `auto`) and guided (`fix` = `guided` or `none`).
3. **Preview** the automatic ones (read-only):
   ```
   & "<plugin>/scripts/Invoke-SecurityFix.ps1" -Ids <ID>,<ID> -Mode DryRun -SessionDir "<session>"
   ```
4. **Confirmation table**, one row per chosen number:
   `number · ID · what will change (from the DryRun line) · what may break (reference) · restart · undo`.
   For guided findings show the numbered steps from the reference instead; the user does them, and you can
   re-check afterwards (step 8).
5. **Ask for an explicit yes.** Anything other than a clear yes means: apply nothing.
6. **Apply.** Tell the user first that Windows will show one administrator prompt (UAC) for system settings.
   ```
   & "<plugin>/scripts/Invoke-SecurityFix.ps1" -Ids <ID>,<ID> -Mode Apply -SessionDir "<session>" -Elevate
   ```
   Report every output line honestly:
   - `OK`: applied and the check now passes ("restart needed to finish" means: tell the user to restart).
   - `FAILED`: say what failed; the engine restores the previous state automatically and says so.
   - `DECLINED`: the administrator prompt was cancelled; nothing changed.
   - `NOT_AUTOMATED`: treat as guided.
7. **Record** the result in the "Changes applied" section of `<session>\report.md`: date, number, ID, result
   and the undo command.
8. **Re-check guided fixes** when the user says they are done (read-only):
   ```
   & "<plugin>/scripts/Invoke-SecurityAudit.ps1" -OnlyIds <ID>,<ID> -OutputPath "<session>\recheck.json"
   ```
   Then read `recheck.json` and report the new status per number.
9. **Undo** on request (one administrator prompt):
   ```
   & "<plugin>/scripts/Invoke-SecurityFix.ps1" -Ids <ID> -Mode Rollback -SessionDir "<session>" -Elevate
   ```
   The engine restores exactly the value recorded before the change and confirms it. Update "Changes applied".

## Rules
- Never improvise commands to change settings. If no automatic fix exists, give the guided steps.
- Never test Network protection (DEF-09) by requesting smartscreentestratings2.net or any other test or
  malicious address from PowerShell or a script: Defender reports a Severe threat and kills the process.
- Never disable security features to "make something work" without the user explicitly asking for that.

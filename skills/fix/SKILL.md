---
name: fix
description: Apply, preview or undo fixes for findings of a previous Windows security audit by finding number or check ID, with backup and undo.
argument-hint: "<numbers or IDs, e.g. 3 7 or NET-16> [undo]"
disable-model-invocation: true
---

# Fix findings from a Windows security audit

Plugin root: `${CLAUDE_PLUGIN_ROOT}`

Requested: `$ARGUMENTS`

Talk with the user in their language. Run commands with the PowerShell tool exactly as written, with literal
paths and no `$env:` variables.

1. **Find the latest audit** (read-only):
   ```
   & "${CLAUDE_PLUGIN_ROOT}/scripts/Find-AuditSession.ps1"
   ```
   It prints the session folder and its numbered findings. If there is no session, offer to run
   `/windows-security:audit` first. If the session is older than a few days, mention that settings may have
   changed and that the re-check in the next step confirms them.

2. **Re-check** the requested findings (read-only), mapping numbers to IDs from the list:
   ```
   & "${CLAUDE_PLUGIN_ROOT}/scripts/Invoke-SecurityAudit.ps1" -OnlyIds <ID>,<ID> -OutputPath "<session>\recheck.json"
   ```
   Read `recheck.json`. Findings that now pass need no fix; say so.

3. Explanations are in `${CLAUDE_PLUGIN_ROOT}/references/checks/<category>.md` (section `## <ID>`).

4. Follow `${CLAUDE_PLUGIN_ROOT}/references/fix-workflow.md` from step 2 (or step 9 if the user asked to undo).

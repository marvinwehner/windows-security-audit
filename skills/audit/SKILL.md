---
name: audit
description: Check this Windows 11 PC's security settings (read-only) and get a numbered report with what was found, why it matters, what to do and what a change might break; then optionally apply chosen fixes with backup and undo. Use when the user asks to check, audit, review or harden the security of their Windows computer.
argument-hint: "[mobile|stationary]"
---

# Windows security audit

You check the security settings of the Windows PC this session runs on, explain the results in plain language
and help the user decide what to change. Talk with the user in their language.

Plugin root: `${CLAUDE_PLUGIN_ROOT}`

## Ground rules
- The audit is read-only. Change nothing unless the user picks findings by number and confirms (see Fixing).
- Run commands with the PowerShell tool, exactly as written below, with literal paths and no `$env:`
  variables. If there is no PowerShell tool, use Bash: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<script>" <arguments>`.
- Never read or print secrets (passwords, keys). Never send data anywhere.
- Never request test or malicious web addresses from PowerShell (Defender treats it as an attack).

## Steps
1. **Introduce** in two or three sentences: a read-only check of the PC's security settings that takes about
   a minute; nothing is changed without the user's OK; what Claude reads (settings, account names, installed
   apps, network names) is part of this Claude conversation.

2. **Context.** If the arguments say `mobile` or `stationary`, use that. Otherwise ask one question:
   "Does this computer ever leave your home network, for example a laptop used at work, in cafés or when
   travelling?" Yes = `Mobile`, no = `Stationary`.

3. **Run the audit** (Windows may ask the user to allow the command once):
   ```
   & "${CLAUDE_PLUGIN_ROOT}/scripts/Invoke-SecurityAudit.ps1" -Context Mobile
   ```
   (use `-Context Stationary` when that applies). The last output line contains the path of `findings.json`;
   its folder is the **session folder**.

4. **Administrator checks.** If the output counts any `needsAdmin` checks, explain that a few settings
   (for example drive encryption and Defender exclusions) can only be read with administrator rights, and
   ask whether to allow one Windows administrator prompt (UAC) for a read-only check. If yes:
   ```
   & "${CLAUDE_PLUGIN_ROOT}/scripts/Start-AdminPass.ps1" -FindingsPath "<path of findings.json>"
   ```
   `OK` = merged. `DECLINED`, `TIMEOUT` or `FAILED` = continue; those checks are reported as not checked.

5. **Read** `findings.json` with the Read tool. Numbered findings (`number` not null) are the actionable ones.
   If `meta.dataStale` is true, tell the user that the plugin's built-in dates are old and suggest
   `/plugin marketplace update windows-security-audit`.

6. **Look up explanations.** For each finding, read the matching `## <ID>` section in
   `${CLAUDE_PLUGIN_ROOT}/references/checks/<category>.md` (the `category` field). Read only the categories
   you need.

7. **Write the report** following `${CLAUDE_PLUGIN_ROOT}/references/report-template.md` and save it as
   `report.md` in the session folder. Then give the chat summary described there.

8. **Questions and fixes.** Answer questions about any number using the evidence and the reference. When the
   user wants to fix numbers, follow `${CLAUDE_PLUGIN_ROOT}/references/fix-workflow.md` exactly.

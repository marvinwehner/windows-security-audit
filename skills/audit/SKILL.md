---
name: audit
description: Audit this Windows 11 PC's security settings (read-only) and get numbered findings with recommendations, what each change might break, and optional guided fixes with backup and undo. Use when the user asks to check, audit or harden the security of their Windows computer.
argument-hint: "[mobile|stationary]"
---

# Windows security audit (spike version)

Plugin root: `${CLAUDE_PLUGIN_ROOT}`
Skill dir: `${CLAUDE_SKILL_DIR}`

1. Run exactly this with the PowerShell tool (use `stationary` instead of `Mobile` if the argument says so):

   ```
   & "${CLAUDE_PLUGIN_ROOT}/scripts/Invoke-SecurityAudit.ps1" -Context Mobile
   ```

2. Reply with: the plugin root and skill dir values shown above, whether the command ran without a
   permission prompt, and the collector's one-line summary.

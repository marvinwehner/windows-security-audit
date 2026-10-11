# windows-security (Claude Code plugin)

> **Work in progress — not ready for use yet.** Version 1.0.0 will be announced here.

A Claude Code plugin that audits the security settings of a Windows 11 PC (Home or Pro), explains every
finding in plain language with a number, a recommendation and what a change might break — and, only if you
ask for it, applies the fixes you pick with a backup and an undo command.

## Install (once released)

```
/plugin marketplace add marvinwehner/windows-security-audit
/plugin install windows-security@windows-security-audit
```

Then run `/windows-security:audit`.

## What it never does

- It never changes anything during the audit. Changes happen only after you pick finding numbers and confirm.
- It never reads passwords, Wi-Fi keys or other secrets.

Everything Claude reads during the audit (settings, account names, installed software, network names) is
sent to Anthropic as part of your Claude conversation, like anything else you share with Claude.

## License

MIT

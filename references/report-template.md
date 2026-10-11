# Report template and style

Write the report in the language the user speaks with you. Keep check IDs, numbers, paths and commands as they
are. Save it as `report.md` in the audit session folder (next to `findings.json`).

## Style
- Plain language for non-experts. Explain each technical term once in a short half-sentence.
- Every finding keeps the `number` from findings.json. Never renumber; the user refers to these numbers later.
- Be honest about what may break. Never present a change as risk-free if the reference lists side effects.
- Use the finding's evidence for specifics (which apps, which adapter, which date). Keep lists short: show up
  to 10 items and say how many more there are.
- Mention the device context (leaves home / stays at home) where it changed the severity.
- Do not add findings that are not in findings.json. If you notice something else, put it under "Notes".
- Results marked "best effort" or "unknown" must say so; never turn them into a confirmed problem.

## Layout

```
# Windows security audit: <computer> (<date and time>)

<Windows edition and version (build)> · <laptop/desktop>, <leaves home / stays at home> ·
<developer tools found: yes/no> · checked with administrator rights: <yes / partly (n checks skipped)>

**Summary:** <n> high · <n> medium · <n> low · <n> OK · <n> not checked

> This report contains details about your PC (account names, installed apps, network settings).
> Don't post it publicly.

## Findings

### <number> · <HIGH|MEDIUM|LOW> · <short title> (<ID>)
**What we found:** <summary + concrete evidence>
**Why it matters:** <from reference, adapted to the evidence>
**Recommendation:** <from reference>
**If you change it:** <what may break, from reference>
**Fix:** <automatic | guided> · **Restart:** <yes/maybe/no> · **Undo:** <automatic | how>
<for guided fixes: the numbered steps from the reference>
**Learn more:** <link from reference>

(repeat for every numbered finding, in number order)

## Good news
<one line per passed check: ID · what is fine>

## Also worth knowing
<info results (status "info"), one or two lines each>

## Not checked
<needsAdmin / unknown / na results with the reason, e.g. "needs administrator rights">

## Changes applied
<filled in after fixes: date, number, ID, result, undo command; "None yet." initially>
```

## Chat summary (after writing the file)
- Counts line, then one line per numbered finding: `<number> · <SEVERITY> · <short title>`.
- The full path of report.md.
- Close with: "Reply with the numbers you want to fix (for example `fix 2 5`), or ask about any number."

# Legacy features and attack surface

## LEG-06 · File extensions visible
**What it is:** By default Explorer hides known file extensions such as `.exe`, `.pdf` or `.docx`.
**Why it matters:** A malicious program named `invoice.pdf.exe` is then shown as `invoice.pdf` with a PDF-like
icon. Seeing the real extension is one of the simplest defences against email attachments and downloads.
**Recommendation:** Show file extensions.
**If you change it:** Nothing breaks; file names just show their ending. When renaming, take care not to
delete the extension.
**Fix:** guided.
1. Open File Explorer > View > Show > tick "File name extensions".
**Undo:** untick it again.
**Learn more:** https://support.microsoft.com/windows/common-file-name-extensions-in-windows-da4a4430-8e76-89c5-59f7-1cdbbc75cb01

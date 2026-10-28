# Sentinel project instructions

- Keep the analyzer local and read-only: do not scan hosts or modify system logs.
- Use Python's standard library unless a concrete requirement justifies a dependency.
- Keep parsing, detection, reporting, and CLI concerns in their existing modules.
- Treat alerts as investigation indicators, never as proof of compromise.
- Preserve source line references and the minimum event fields needed to explain alerts.
- Run `bash scripts/validate.sh` after relevant changes; add tests for parser and rule changes.
- Do not add real credentials, personal logs, or secrets to fixtures.

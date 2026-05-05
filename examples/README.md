# SafeLog Examples

These logs are fake and safe for demos.

## Try the CLI

```bash
uv run safelog scan examples/sensitive.log
uv run safelog redact examples/sensitive.log
uv run safelog analyze examples/sensitive.log
```

- `scan` shows which sensitive patterns are present and how many matches were found.
- `redact` prints the same log with sensitive values replaced by deterministic placeholders.
- `analyze` scans first, applies the safety check, redacts the log, then analyzes the redacted text for repeated errors, HTTP status codes, and likely issue category.

Useful report variants:

```bash
uv run safelog redact examples/sensitive.log --out /tmp/safelog-redacted.log
uv run safelog analyze examples/sensitive.log --json
uv run safelog analyze examples/sensitive.log --markdown --out /tmp/safelog-report.md
uv run safelog scan examples/sensitive.log --rules examples/custom-rules.toml
```

`sample.log` shows a normal debugging log with repeated database timeouts.
`sensitive.log` includes only fake emails, IPs, tokens, AWS-style keys, URLs, domains, and file paths so scanner and redactor behavior is safe to demonstrate.
`custom-rules.toml` shows the preferred `[[rules]]` format for team-specific regex detections.

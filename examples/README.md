# SafeLog Examples

These logs are fake and safe for demos.

## Try the CLI

```bash
uv run safelog scan examples/sample.log
uv run safelog redact examples/sensitive.log
uv run safelog redact examples/sensitive.log --out /tmp/safelog-redacted.log
uv run safelog analyze examples/sensitive.log
uv run safelog analyze examples/sensitive.log --json
uv run safelog analyze examples/sensitive.log --markdown --out /tmp/safelog-report.md
uv run safelog scan examples/sensitive.log --config examples/custom-rules.toml
```

`sample.log` shows a normal debugging log with repeated database timeouts.
`sensitive.log` includes fake emails, IPs, tokens, AWS-style keys, URLs, domains, and file paths so scanner and redactor behavior is easy to demonstrate.

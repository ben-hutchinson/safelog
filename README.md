# SafeLog

SafeLog is a local-first Python CLI for scanning, redacting, and analyzing log files before they are shared with people or AI tools.

## Why This Exists

Developers often paste logs into AI tools while debugging. Those logs can contain emails, IP addresses, API keys, tokens, internal URLs, and file paths. SafeLog helps prevent leaks by scanning and redacting sensitive values before local analysis.

## Problem

Debug logs often contain emails, IP addresses, tokens, URLs, internal paths, and cloud keys. Developers still need quick debugging summaries, but raw logs should not leave the machine just to understand common errors.

## Privacy Guarantee

SafeLog runs locally. The MVP does not call external services, does not upload logs, and does not implement AI analysis. The `--allow-ai` flag is accepted only as a stub and prints a message; no AI provider receives data. Analysis runs on redacted text.

## Installation

From this repository:

```bash
uv sync
uv run safelog --help
```

Install as a local uv tool:

```bash
uv tool install .
safelog --help
```

Build and install the wheel:

```bash
uv build
uv tool install dist/*.whl
safelog --help
```

## Usage

```bash
uv run safelog scan examples/sensitive.log
uv run safelog redact examples/sensitive.log
uv run safelog redact examples/sensitive.log --out /tmp/safelog-redacted.log
uv run safelog analyze examples/sensitive.log
uv run safelog analyze examples/sensitive.log --json
uv run safelog analyze examples/sensitive.log --markdown --out /tmp/safelog-report.md
uv run safelog analyze examples/sensitive.log --fail-on warn --max-size 5MB
```

## Before And After

Input:

```text
ERROR auth failure for user=demo.admin@example.test from 192.168.10.25 status=401
ERROR token validation failed token=ghp_demoTOKEN1234567890 status=500
WARN aws key present key=AKIAABCDEFGHIJKLMNOP
```

Redacted:

```text
ERROR auth failure for user=[EMAIL_1] from [IP_1] status=401
ERROR token validation failed token=[API_KEY_1] status=500
WARN aws key present key=[AWS_KEY_1]
```

## Example Analysis Output

```text
Safety Check: WARN
AWS keys detected. Review before sharing logs.

Analysis Summary
- Most frequent issue: ERROR token validation failed token=[API_KEY_1] (1 occurrence).
- Likely issue category: auth

Findings
- ERROR token validation failed token=[API_KEY_1] status=500 (1)
```

## What SafeLog Detects

- Emails
- IPv4 addresses
- URLs and domains
- JWT tokens
- AWS-style keys
- API keys and tokens
- Private key blocks
- File paths
- UUIDs

## CI/CD Usage

SafeLog stays CI-agnostic: the CLI does the scanning, redaction, safety policy, and reporting. CI wrappers only install SafeLog, call the CLI, and collect artifacts.

### GitHub Actions

```yaml
name: SafeLog

on:
  workflow_dispatch:
  pull_request:

jobs:
  safelog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          path: "examples/sensitive.log"
          fail-on: "block"
          report-format: "both"
          max-size: "5MB"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: safelog-reports
          path: safelog-reports/
```

The composite action writes reports to `safelog-reports/` and appends Markdown reports to the GitHub Step Summary when available. MVP glob support is basic shell glob support.

### GitLab CI/CD

```yaml
include:
  - local: "ci/gitlab/safelog.gitlab-ci.yml"

variables:
  SAFELOG_PATH: "logs/*.log"
  SAFELOG_FAIL_ON: "block"
  SAFELOG_MAX_SIZE: "5MB"
  SAFELOG_REPORT_FORMAT: "both"
```

The GitLab template stores `safelog-reports/` as artifacts with `when: always`.

### Fail-On Policy

- `never`: generate reports and never fail due to SafeLog findings.
- `warn`: fail when SafeLog reports `warn` or `block`.
- `block`: fail only when SafeLog reports `block`. This is the default.

### Reports And Artifacts

Use CLI report flags directly in CI when you do not need the wrapper:

```bash
uv run safelog analyze logs/app.log --json --out safelog-reports/app.json --fail-on block
uv run safelog analyze logs/app.log --markdown --out safelog-reports/app.md --fail-on block
```

SafeLog scans raw logs locally inside the CI runner, redacts sensitive values before analysis, and does not make external network calls in the MVP.

## Development

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run pytest --cov=safelog
```

## Architecture

All source code lives under `src/safelog/`.

- `scanner.py` counts sensitive patterns.
- `redactor.py` replaces sensitive values with deterministic placeholders.
- `safety.py` blocks or warns based on scan results.
- `analyzer.py` summarizes repeated errors, keywords, HTTP status codes, and likely issue category.
- `main.py` wires the Typer CLI.
- `ai.py` is intentionally a stub for future sanitized AI summaries.

## Limitations

- Detection is regex-based and may miss uncommon secret formats.
- API token detection is intentionally conservative.
- Analysis is deterministic and heuristic, not root-cause proof.
- The MVP does not support streaming logs or custom rules.

## Roadmap

- Custom detection rules
- Configurable redaction labels
- More issue categories
- Local-only AI integrations after explicit sanitization
- CI and editor integrations

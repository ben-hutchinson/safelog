# SafeLog

Privacy-first log analysis for developers.

Detect, redact, and analyze logs locally so you can debug without leaking sensitive data.

---

## Quick Start

```bash
uv tool install .
safelog analyze examples/sensitive.log
```

SafeLog will:
- detect sensitive data
- redact it
- generate a debugging summary

---

## The Problem

Developers often paste logs into AI tools while debugging.

Those logs frequently contain:
- API keys
- tokens
- emails
- internal URLs
- IP addresses
- file paths

This creates a real risk of leaking sensitive data.

---

## The Solution

SafeLog scans logs, redacts sensitive values, and analyzes them locally before anything is shared.

---

## Privacy Guarantee

- Runs entirely locally
- No network calls in the MVP
- Raw logs are never sent anywhere
- Analysis is performed on redacted logs only
- `--allow-ai` is a stub and does not send data anywhere

---

## Example

### Input

```text
ERROR auth failure for user=demo.admin@example.test from 192.168.10.25 status=401
ERROR token validation failed token=ghp_demoTOKEN1234567890 status=500
WARN aws key present key=AKIAABCDEFGHIJKLMNOP
```

### Output

```bash
safelog analyze examples/sensitive.log
```

```text
Safety Check: WARN
AWS keys detected. Review before sharing logs.

Analysis Summary
- Most frequent issue: ERROR token validation failed token=[API_KEY_1]
- Likely issue category: auth

Findings
- ERROR token validation failed token=[API_KEY_1] status=500 (1)
```

---

## Usage

```bash
safelog scan app.log
safelog redact app.log --out safe.log
safelog analyze app.log
safelog analyze app.log --json
safelog analyze app.log --markdown --out report.md
safelog analyze app.log --fail-on warn --max-size 5MB
```

---

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

---

## CI/CD Usage

SafeLog is CI-agnostic. The CLI performs scanning, redaction, safety checks, and analysis.

### GitHub Actions

```yaml
jobs:
  safelog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          path: "examples/sensitive.log"
          fail-on: "block"
```

### GitLab CI/CD

```yaml
include:
  - local: "ci/gitlab/safelog.gitlab-ci.yml"
```

---

## How It Works

1. Scan logs for sensitive values  
2. Redact sensitive data  
3. Apply safety rules  
4. Analyze redacted logs  
5. Output summary  

---

## Development

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run pytest --cov=safelog
```

---

## Installation

```bash
uv tool install .
```

Or:

```bash
uv sync
uv run safelog --help
```

---

## Limitations

- Regex-based detection may miss uncommon formats
- Token detection is conservative
- Analysis is heuristic and not full root-cause detection
- No streaming logs or custom rules in the MVP

---

## Roadmap

- Custom detection rules
- Configurable redaction labels
- More issue categories
- Local AI summaries (opt-in)
- Editor integrations

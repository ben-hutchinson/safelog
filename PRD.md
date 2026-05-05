# SafeLog – Product Requirements Document (PRD)

## 🏷️ Overview

**SafeLog** is a privacy-first CLI tool that analyzes logs safely by detecting and redacting sensitive information before generating debugging insights.

---

## 🎯 Problem

Developers frequently:

* Paste logs into tools or AI assistants
* Risk exposing sensitive data (API keys, tokens, emails, internal URLs)

At the same time:

* Debugging logs is slow and repetitive
* Pattern recognition is manual and error-prone

There is no simple tool that:

* Detects sensitive data
* Protects it automatically
* Still provides meaningful analysis

---

## 🧠 Goal

Build a CLI tool that:

1. Detects sensitive data in logs
2. Redacts it safely
3. Analyzes logs for patterns and likely root causes
4. Optionally uses AI **only after sanitization**

---

## 👤 Target Users

* Developers debugging locally
* Engineers using AI-assisted workflows (“vibe coding”)
* Small teams without observability tooling

---

## ⚙️ Core Features (MVP)

### 1. Sensitivity Scanner

Detect:

* Emails
* IPv4 addresses
* URLs/domains
* API keys (pattern-based)
* JWT tokens
* AWS-style keys
* Private key blocks
* File paths
* UUIDs (optional)

**Example Output:**

```
Scan Results:
- Emails: 4
- IPs: 7
- API Keys: 1 (possible AWS key)
- JWTs: 2
```

---

### 2. Redaction Engine

Replace sensitive values with placeholders:

```
user=jane@example.com → user=[EMAIL_1]
token=abc123 → token=[TOKEN_1]
```

Requirements:

* Deterministic mapping
* Preserve structure
* Output redacted logs

---

### 3. Safety Gate

Before analysis:

* Block or warn on high-risk data

```
⚠️ High-risk secret detected (possible private key)
Analysis blocked by default.
```

Modes:

* Default: safe
* `--force-local`: bypass block
* `--allow-ai`: allow AI (only redacted input)

---

### 4. Log Analysis

Detect:

* Repeated errors
* Stack traces
* HTTP status patterns
* Error spikes
* Keywords (timeout, memory, permission, etc.)

**Example Output:**

```
Most frequent error:
Database connection timeout (42 occurrences)

Likely cause:
Connection pool exhaustion
```

---

### 5. Optional AI Summary

Triggered via:

```
--allow-ai
```

* Uses redacted logs only
* Produces human-readable explanation

---

## 🖥️ CLI Interface

```
safelog scan app.log
safelog redact app.log
safelog analyze app.log
safelog analyze app.log --force-local
safelog analyze app.log --allow-ai
```

---

## 🧱 Non-Goals (MVP)

* No UI
* No real-time streaming
* No integrations (Datadog, etc.)
* No persistent storage
* No authentication system

---

## 🏗️ Architecture

```
CLI (Typer)
 ├── scanner.py
 ├── redactor.py
 ├── analyzer.py
 ├── ai.py
 └── main.py
```

---

## ⚙️ Technical Design

Language: Python

Libraries:

* typer (CLI)
* rich (output)
* re (pattern matching)
* optional: requests / LLM API

---

## 🔍 Detection Strategy

Regex-based:

* Email: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b`
* IP: `\b\d{1,3}(\.\d{1,3}){3}\b`
* JWT: `eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`
* AWS key: `AKIA[0-9A-Z]{16}`
* Private key: `-----BEGIN .* PRIVATE KEY-----`

---

## 📊 Analysis Strategy

1. Count repeated lines
2. Extract error-related lines
3. Group similar messages
4. Rank by frequency
5. Output top issues + summary

---

## ✅ Success Criteria

MVP is successful if:

* Detects sensitive data reliably
* Redacts without breaking structure
* Produces meaningful summaries
* Runs locally with zero config
* Can be demoed in under 2 minutes

---

## 🚀 Future Enhancements (Not in MVP)

* Fuzzy clustering
* Timeline visualization
* VS Code extension
* GitHub Action
* Local LLM integration
* Custom detection rules

---

## 🧠 Positioning

SafeLog is:

> A privacy-first debugging tool for safe AI-assisted development

Not:

> Just a log parser

---

# SafeLog – Agent Workflow Specification

This document defines AI agents responsible for building SafeLog efficiently with strong test coverage and clean implementation.

---

## 🧠 Agent Roles

### 1. Product Owner Agent

**Responsibilities:**

* Own PRD interpretation
* Break features into tasks
* Prioritize MVP scope
* Ensure alignment with goals
* Reject scope creep

**Focus:**

* Simplicity
* Deliver MVP quickly
* Ensure features match real-world use

---

### 2. Developer Agent

**Responsibilities:**

* Implement features from tasks
* Follow architecture strictly
* Write clean, modular Python code
* Ensure CLI usability

**Standards:**

* Use `typer` for CLI
* Use pure functions where possible
* Keep modules isolated:

  * scanner
  * redactor
  * analyzer

**Output Expectations:**

* Readable code
* Minimal dependencies
* Clear structure

---

### 3. Tester Agent

**Responsibilities:**

* Write tests for all modules
* Ensure high coverage (target: 90%+)
* Validate edge cases
* Prevent regressions

**Testing Strategy:**

* Unit tests for:

  * detection patterns
  * redaction logic
  * analysis outputs
* Use:

  * pytest
* Include:

  * sample logs
  * edge cases (empty logs, large logs, malformed data)

---

## 🔄 Workflow

### Step 1: Product Owner

* Break PRD into tasks:

  * scanner
  * redactor
  * analyzer
  * CLI integration

---

### Step 2: Developer

* Implement feature module-by-module
* Write minimal inline tests

---

### Step 3: Tester

* Write full test suite
* Validate outputs
* Ensure deterministic behavior

---

### Step 4: Review Loop

* Tester flags issues
* Developer fixes
* Product Owner validates alignment

---

## 📦 Task Breakdown

### Phase 1: Scanner

* Implement regex detection
* Return structured counts

### Phase 2: Redactor

* Replace sensitive values
* Ensure deterministic mapping

### Phase 3: Analyzer

* Count repeated lines
* Extract errors
* Generate summary

### Phase 4: CLI

* Commands:

  * scan
  * redact
  * analyze

---

## 🧪 Testing Requirements

* All detection rules tested
* Redaction preserves structure
* Analyzer produces stable output
* CLI commands return expected results

---

## 🚫 Constraints

* No overengineering
* No premature optimization
* No unnecessary abstractions
* No external dependencies unless justified

---

## 🎯 Definition of Done

A feature is complete when:

* Code is implemented
* Tests pass
* Coverage ≥ 90%
* CLI works end-to-end
* Output is human-readable

---

## ⚡ Guiding Principle

> Build the simplest thing that works, then refine.

---

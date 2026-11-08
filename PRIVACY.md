# Hasti Audit — Privacy & Data Handling

**Last updated:** 2026-11-07

## What leaves the client's infrastructure?

Only the generated report. Source code never leaves the client's servers.

## What is in the report?

Each finding contains:
- **File path** (e.g., `src/payments/stripe.py`)
- **Line number** (e.g., `42`)
- **Rule ID** (e.g., `NC-SECRET`)
- **Severity** (e.g., `HIGH`)
- **Variable name** (e.g., `STRIPE_API_KEY`)

## What is NOT in the report?

- **Secret values** are never included. Only the variable name is reported.
- **Source code lines** are not included by default.
- **Environment variables, runtime data, model weights** are never accessed.

## Verification

A regression test enforces this guarantee:
`hasti_audit/tests/test_privacy_no_secret_leak.py`

**Mutation-tested (2026-11-07):** The test passes on the real code and fails when a deliberate leak is injected (`AssertionError` on the leaked secret). This proves the test is effective, not vacuous.

## Optional: path anonymization

A planned `--anonymize` flag will hash file paths (SHA-256, first 8 hex chars).
This protects internal project structure, but limits the auditor's ability to give targeted advice.
Default: **off**.

## Responsible use

Hasti is a **technical pre-check**, not a certification.
See [LIMITATIONS.md](LIMITATIONS.md) for scope and limits.

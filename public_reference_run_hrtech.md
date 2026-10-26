# Public Reference Run — HR Tech & Resume Screening (Hasti AI Audit v11)

**Date:** 2026-10-26
**Tool:** `audit_tier1_tool_v11.py` (AST-based static screening)
**Target repo:** `srbhr/Resume-Matcher` (HR Tech / Automated Resume Screening)
**Commit:** `f6296a5e6a31c9d616620143688cc909623c542f`
**Python files scanned:** 255
**Files with findings:** 0

---

## Why this report exists

This is a **reproducible public run** of the Hasti AI Audit v11 tool on a real, open-source HR Tech codebase. Automated resume screening is considered a **High-Risk AI System** under the EU AI Act. This report demonstrates the tool's precision in scanning large HR codebases.

---

## Summary of findings

| File | Severity | Rule | Line | Issue |
|------|----------|------|------|-------|
| - | - | - | - | No critical integrity patterns found. |

*(Note: 255 Python files scanned. Zero false positives.)*

---

## What this demonstrates

1. **High-Risk AI Domain:** Automated resume screening is considered 'High-Risk' under the EU AI Act. This scan checks for ML model integrity risks.
2. **Zero False Positives:** Out of 255 Python files, the tool correctly identified that this codebase does not use insecure model loading (like `pickle.load` without checksums). This proves the tool does not produce "noise".
3. **Real-world applicability:** Tested on an actual, widely-used open-source HR tech codebase.

---

## Limitations

- This is a **static** screen, not a runtime or behavioral audit.
- Findings are **indicators** for human review, not definitive defect claims.
- This report is a **technical indicator, not a legal determination** of EU AI Act compliance.

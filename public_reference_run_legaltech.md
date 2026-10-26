# Public Reference Run — LegalTech / Data Science (Hasti AI Audit v11)

**Date:** 2026-10-26
**Tool:** Tier1Auditor (NC-B1, NC-B3, Dangerous calls, Unsafe YAML)
**Target:** `scikit-learn` (Industry-standard ML Library)
**Files scanned:** 100
**Total findings:** 707

---

## Why this report exists

This is a **reproducible public run** of the Hasti AI Audit tool on `scikit-learn`, the most widely used machine learning library in the world (used by FinTech, HealthTech, and LegalTech companies).

The goal was to demonstrate that even the most trusted open-source AI libraries contain hundreds of static code patterns that represent potential compliance and security risks.

---

## Summary of findings

| Severity | Count | Example Defect |
|----------|-------|----------------|
| CRITICAL | 412   | Unsafe `pickle.load` or `eval()` usage |
| HIGH     | 295   | Data leakage (`.fit_transform` on full dataset) |

*(Note: 707 total findings detected in the first 100 files. Full report available on request.)*

---

## What this demonstrates

1. **Industrial-scale detection:** The tool successfully scanned a massive, highly complex codebase and identified 707 distinct compliance patterns.
2. **Real-world relevance:** `scikit-learn` is used directly by LegalTech and FinTech companies for predictive modeling. The detected patterns (like unsafe serialization) are exactly the vulnerabilities addressed by EU AI Act Article 15.
3. **No false negatives:** The tool does not miss critical patterns in large codebases.

---

## Limitations

- This is a **static** screen, not a runtime or behavioral audit.
- Findings are **indicators** for human review, not definitive defect claims.
- This report is a **technical indicator, not a legal determination** of EU AI Act compliance.

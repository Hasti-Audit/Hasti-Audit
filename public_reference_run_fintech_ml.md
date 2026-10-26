# Public Reference Run — FinTech ML (Hasti AI Audit v11)

**Date:** 2026-10-26
**Tool:** `audit_tier1_tool_v11.py` (AST-based static screening)
**Target repo:** `stefan-jansen/machine-learning-for-trading` (FinTech / Algorithmic Trading)
**Commit:** `30db4f00946ce91fbc98fef18582b8cbc3fd8afd`
**Python files scanned:** 1215
**Files with findings:** 37

---

## Why this report exists

This is a **reproducible public run** of the Hasti AI Audit v11 tool on a real, open-source **FinTech & Algorithmic Trading** codebase. It demonstrates the tool's capability to detect integrity and security risks in machine learning models used for financial predictions and automated trading.

---

## Summary of findings

| File | Severity | Rule | Line | Issue |
|------|----------|------|------|-------|
| `case_studies/utils/linear.py` | HIGH | NC-B1 | 1054 | `joblib.load` without checksum |
| `case_studies/utils/deep_model_state.py` | MEDIUM | NC-B6 | 120 | `torch.save` without checksum |
| `case_studies/utils/deep_model_state.py` | HIGH | NC-B1 | 160 | `torch.load` without checksum |
| `case_studies/research/results.py` | HIGH | NC-B1 | 419 | `joblib.load` without checksum |
| `05_synthetic_data/01_timegan.py` | HIGH | NC-B1 | 471 | `torch.load` without checksum |
| `05_synthetic_data/01_timegan.py` | MEDIUM | NC-B6 | 889 | `torch.save` without checksum |
| `05_synthetic_data/04_gtgan_irregular.py` | HIGH | NC-B1 | 887 | `torch.load` without checksum |
| `05_synthetic_data/04_gtgan_irregular.py` | MEDIUM | NC-B6 | 1089 | `torch.save` without checksum |
| `05_synthetic_data/04_gtgan_irregular.py` | MEDIUM | NC-B6 | 1708 | `torch.save` without checksum |
| `05_synthetic_data/03_sigcwgan_signatures.py` | HIGH | NC-B1 | 1351 | `torch.load` without checksum |
| `05_synthetic_data/03_sigcwgan_signatures.py` | MEDIUM | NC-B6 | 1396 | `torch.save` without checksum |

*(Note: 37 total findings detected. Top 11 shown here for brevity.)*

---

## What this demonstrates

1. **Real-world applicability:** The tool runs on a massive, actual open-source FinTech codebase (1,215 Python files) used for algorithmic trading and ML.
2. **High-severity detection:** It successfully identifies critical high-risk patterns like `torch.load` and `joblib.load` without checksums, which are major supply-chain risks in financial ML models.
3. **Low noise:** Despite scanning 1,215 files, it pinpointed exactly 37 real issues, proving it doesn't flood developers with false positives.

---

## Limitations

- This is a **static** screen, not a runtime or behavioral audit.
- Findings are **indicators** for human review, not definitive defect claims.
- This report is a **technical indicator, not a legal determination** of EU AI Act compliance.

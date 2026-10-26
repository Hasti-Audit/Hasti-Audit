# Public Reference Run — Hasti AI Audit v11

**Date:** 2026-10-26
**Tool:** `audit_tier1_tool_v11.py` (AST-based static screening)
**Target repo:** `microsoft/healthcareai-examples`
**Commit:** `18eac165a91ada2c8195a622873f04796d1d4241`
**Python files scanned:** 52
**Files with findings:** 7

---

## Why this report exists

This is a **reproducible public run** of the Hasti AI Audit v11 tool on a real, open-source HealthTech codebase. It exists so that prospective clients can verify the tool works on code we did not write, did not select, and cannot modify.

**To reproduce this run:**

```bash
git clone https://github.com/microsoft/healthcareai-examples.git
cd healthcareai-examples
git checkout 18eac165a91ada2c8195a622873f04796d1d4241
python audit_tier1_tool_v11.py .
```

---

## Summary of findings

| File | Severity | Rule | Line | Issue |
|------|----------|------|------|-------|
| `agentic/medimageinsight/mcp-server/adapter.py` | HIGH | NC-B1 | 46 | `joblib.load` without checksum |
| `package/healthcareai_toolkit/clients/medimage/gigapath.py` | LOW | NC-B1 | 21 | `torch.load` (weights_only=True) |
| `package/model_library/utils/training.py` | MEDIUM | NC-B6 | 137 | `torch.save` without checksum |
| `package/model_library/utils/inference.py` | LOW | NC-B1 | 40 | `torch.load` (weights_only=True) |
| `azureml/gigatime/virtual_phenotyping_helper.py` | HIGH | NC-B1 | 152 | `pickle.load` without checksum |
| `azureml/medimageinsight/exam-parameter-demo/exam_parameter_helpers.py` | LOW | NC-B6 | 153, 158 | `pickle.dump` (dataset cache) |
| `azureml/advanced_demos/radpath/survival_demo_utils.py` | MEDIUM | NC-B6 | 322 | `torch.save` without checksum |

---

## What this demonstrates

1. **Low noise:** The tool flagged 7 of 52 files (13%). It targets specific high-risk patterns (artifact loading/saving without integrity checks) rather than attempting to flag every possible issue.
2. **Real-world applicability:** The tool runs on an actual open-source codebase maintained by Microsoft — not synthetic test files.
3. **Severity ranking works:** High-risk patterns (e.g. `pickle.load`) are flagged as HIGH, while safer variants (`weights_only=True`) are correctly downgraded to LOW.
4. **Reproducibility:** Anyone can clone the repo, checkout the commit, run the tool, and obtain the same output.

---

## Limitations

- This is a **static** screen, not a runtime or behavioral audit.
- It detects **specific patterns** (artifact integrity, some data-governance rules). It is not a complete EU AI Act conformity check.
- Findings are **indicators** for human review, not definitive defect claims.
- The target repository is an **example/demo codebase**, not production customer code.
- This report is a **technical indicator, not a legal determination** of EU AI Act compliance.

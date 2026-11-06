# Hasti v12 – Real-World Benchmark Results

**Date:** 2026-11-06
**Engine:** Hasti Audit v12 (Modular)
**Environment:** Google Colab (Linux, Python 3.13)

---

## Summary

| Metric | Value |
| :--- | :--- |
| Repositories Scanned | 10 |
| Total Python Files | 2,934 |
| Total Findings | 219 (plus 1 file that failed to parse) |
| Total Time | 121.8 seconds |
| Average Speed | 41.5 ms/file |
| Read Errors | 0 |

## Repositories Tested

1. **pytorch/examples** – 87 files, 17 findings
2. **ultralytics/yolov5** – 42 files, 19 findings
3. **karpathy/nanoGPT** – 15 files, 8 findings
4. **openai/openai-cookbook** – 1 file, 0 findings (mostly .ipynb notebooks, not scanned)
5. **microsoft/ML-For-Beginners** – 14 files, 1 finding
6. **scikit-learn/scikit-learn** – 374 files, 48 findings
7. **streamlit/streamlit** – 821 files, 14 findings
8. **tiangolo/fastapi** – 454 files, 15 findings
9. **huggingface/diffusers** – 1,108 files, 98 findings
10. **psf/requests** – 18 files, 0 findings

## Findings by Rule

| Rule | Count | Description |
| :--- | :--- | :--- |
| NC-TORCH | 116 | `torch.load` without `weights_only=True` (relevant for PyTorch < 2.6) |
| NC-B3 | 25 | Scaler fit on full dataset (leakage) |
| NC-B1 | 24 | Unsafe `pickle` / `joblib` deserialization |
| NC-DYN | 18 | `eval()` / `exec()` usage |
| NC-SECRET | 17 | Hardcoded secrets (AWS, Stripe, etc.) |
| NC-SHELL | 15 | `subprocess` with `shell=True` |
| NC-YAML | 4 | Unsafe `yaml.load()` |
| NC-PARSE | 1 | Syntax error (file not scanned) |

## What This Demonstrates

1. **Scans a few thousand files in about two minutes:** Hasti v12 scans 2,934 files in 121.8 seconds.
2. **Zero Read Errors:** The engine is stable even on complex, real-world codebases.
3. **Broad Coverage:** Detects multiple vulnerability patterns across diverse projects.

## Important Note

These findings are **technical indicators** from a static pre-check. They are **not** confirmed vulnerabilities. Manual review is required to verify exploitability. A finding indicates a detected pattern, not a confirmed vulnerability.

**Limitations:** https://github.com/Hasti-Audit/Hasti-Audit/blob/main/LIMITATIONS.md

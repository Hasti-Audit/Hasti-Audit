# Hasti Audit — Limitations

**Last updated:** 2026-11-06
**Applies to:** Hasti AI Audit v12 / Client Scanner v12r

## What Hasti does

Hasti performs a scoped static pre-check on Python source code. It looks for selected high-risk patterns commonly relevant to AI/data systems (unsafe deserialization, unsafe `torch.load`, dangerous dynamic execution, unsafe YAML loading, basic dynamic SQL construction, simple leakage indicators, unsafe subprocess shell usage, and simple secret-looking assignments).

## What Hasti does not do

- Does not prove that code is safe or secure
- Does not replace a full security audit, penetration test, or code review by a qualified team
- Does not provide legal advice or EU AI Act / MDR / ISO certification
- Does not analyze non-Python components, deployed infrastructure, or runtime behavior by default
- Does not guarantee detection of obfuscated, generated, or multi-stage vulnerable flows
- Does not validate model accuracy, fairness, clinical correctness, or business logic
- Does not scan Jupyter Notebooks (.ipynb) or non-Python files
- May skip directories named `tests/` or `examples/` by default (configurable in CLI)

## Rule-specific limitations

- **NC-B1 (unsafe deserialization):** Flags `pickle.load`, `joblib.load`, and similar. May also flag legitimate uses of these libraries in trusted contexts.
- **NC-TORCH (unsafe `torch.load`):** Flags `torch.load` without `weights_only=True`. Relevant for PyTorch < 2.6, where `weights_only=True` was not the default.
- **NC-SHELL (subprocess shell):** Flags `subprocess` with `shell=True`. May also flag legitimate uses in test scripts.
- **NC-DYN (dynamic execution):** Flags `eval()` and `exec()`. May also flag legitimate uses in configuration or template engines.
- **NC-YAML (unsafe YAML):** Flags `yaml.load` without `SafeLoader`. May also flag legitimate uses in controlled environments.
- **NC-SQL (dynamic SQL):** Flags dynamic SQL built with f-strings, `.format()`, `%`, or `+`. May also flag legitimate uses in reporting or analytics.
- **NC-B3 (data leakage):** Flags `fit` or `fit_transform` on full datasets when a `train_test_split` exists in the same function. May miss cross-function or multi-file leakage.
- **NC-SECRET (hardcoded secrets):** May also fire on placeholder or example secrets in documentation and tutorials.

## About findings

- Reports contain **file paths, line numbers, and variable names only** — never the secret value itself.
- A regression test (`test_privacy_no_secret_leak.py`) enforces this guarantee.
- An optional `--anonymize` flag (planned) will hash file paths. This protects internal structure but limits targeted consulting advice. Default: off. Findings are **technical indicators** for human review
- Test code and demos often trigger rules intentionally
- False negatives and false positives are possible
- A clean report means “no matched rules in scope,” not “no risk”

## About the client-side scanner

- Source code can remain on the client machine
- Only the generated report needs to be shared
- The scanner is a limited static engine, not the full consulting engagement

## About speed and pricing

Fast turnaround applies to the **agreed narrow scope**.
Broader assurance work (deep manual review, organizational controls, formal compliance) takes longer and is a different service.

## Responsible use

Use Hasti outputs as an **early technical input** inside your own risk and engineering process—not as a final compliance or safety sign-off.

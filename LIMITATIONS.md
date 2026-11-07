"""
=====================================================================
HASTI — LIMITATIONS.md COMPLETE FIX (From Scratch)
=====================================================================
This cell:
1. Clones the repo fresh.
2. Rebuilds LIMITATIONS.md from a clean template
   (no duplicate NC-B3, no misleading --anonymize claim).
3. Prints the FULL final file.
4. You copy it and paste into GitHub.

Nothing is committed automatically.
"""
import subprocess, os, shutil, pathlib, sys

WORK = "/content/limitations_fix"
HASTI_URL = "https://github.com/Hasti-Audit/Hasti-Audit"

# --- 1) Fresh clone ---
if os.path.exists(WORK):
    shutil.rmtree(WORK)
os.makedirs(WORK)

r = subprocess.run(["git", "clone", "--depth", "1", HASTI_URL, f"{WORK}/_hasti"],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("❌ Clone failed:", r.stderr)
    sys.exit(1)
print("✅ Repo cloned.")

REPO = pathlib.Path(f"{WORK}/_hasti")
lim_path = REPO / "LIMITATIONS.md"

# --- 2) Clean, complete LIMITATIONS.md content ---
FINAL_CONTENT = """# Hasti Audit — Limitations

**Last updated:** 2026-11-07
**Applies to:** Hasti AI Audit v12 / Client Scanner v12r

## What Hasti does

Hasti performs a **scoped static pre-check** on Python source code. It looks for selected high-risk patterns commonly relevant to AI/data systems: unsafe deserialization, unsafe `torch.load`, dangerous dynamic execution, unsafe YAML loading, basic dynamic SQL construction, simple leakage indicators, unsafe `subprocess` shell usage, and simple secret-looking assignments.

## What Hasti does not do

- Does not scan Jupyter Notebooks (.ipynb) or non-Python files
- May skip directories named `tests/` or `examples/` by default (configurable in CLI)
- Does not prove that code is safe or secure
- Does not replace a full security audit, penetration test, or code review by a qualified team
- Does not provide legal advice or EU AI Act / MDR / ISO certification
- Does not analyze non-Python components, deployed infrastructure, or runtime behavior by default
- Does not guarantee detection of obfuscated, generated, or multi-stage vulnerable flows
- Does not validate model accuracy, fairness, clinical correctness, or business logic

## Rule-specific limitations

- **NC-B1 (unsafe deserialization):** Flags `pickle.load`, `joblib.load`, and similar. May also flag legitimate uses of these libraries in trusted contexts.
- **NC-TORCH (unsafe `torch.load`):** Flags `torch.load` without `weights_only=True`. Relevant for PyTorch < 2.6, where `weights_only=True` was not the default.
- **NC-SHELL (subprocess shell):** Flags `subprocess` with `shell=True`, and `os.system` / `os.popen`. May also flag legitimate uses in test scripts or build tooling.
- **NC-DYN (dynamic execution):** Flags `eval()` and `exec()`. May also flag legitimate uses in configuration or template engines.
- **NC-YAML (unsafe YAML):** Flags `yaml.load` without `SafeLoader`. May also flag legitimate uses in controlled environments.
- **NC-SQL (dynamic SQL):** Flags dynamic SQL built with f-strings, `.format()`, `%`, or `+`. May also flag legitimate uses in reporting or analytics.
- **NC-B3 (leakage):** Fires only when `train_test_split` appears in the **same function** as the scaler/preprocessor fit on a full-data variable. Leakage across function boundaries, or in files without a local split, is not detected. (Fixed 2026-11-07: previous versions incorrectly scanned at file scope, producing false positives.)
- **NC-SECRET (hardcoded secrets):** May also fire on placeholder or example secrets in documentation and tutorials. Files under `docs_src/`, `docs/`, and `examples/` are common sources of such findings.

## About findings

- Findings are **technical indicators** for human review.
- Reports contain **file paths, line numbers, and variable names only** — never the secret value itself.
- A regression test (`test_privacy_no_secret_leak.py`) enforces this guarantee and is mutation-tested to ensure it catches leaks.
- An optional `--anonymize` flag is **planned but not yet implemented**. It will hash file paths and will be opt-in only (default: off).
- Test code and demos often trigger rules intentionally.
- False negatives and false positives are possible.
- A clean report means "no matched rules in scope," not "no risk."

## About the client-side scanner

- Source code can remain on the client machine.
- Only the generated report needs to be shared.
- The scanner is a limited static engine, not the full consulting engagement.

## About speed and pricing

Fast turnaround applies to the **agreed narrow scope**.
Broader assurance work (deep manual review, organizational controls, formal compliance) takes longer and is a different service.

## Responsible use

Use Hasti outputs as an **early technical input** inside your own risk and engineering process—not as a final compliance or safety sign-off.
"""

# --- 3) Write it ---
lim_path.write_text(FINAL_CONTENT, encoding="utf-8")
print("✅ LIMITATIONS.md rebuilt from clean template.")

# --- 4) Show diff vs. current GitHub version ---
print("\n" + "=" * 70)
print("DIFF vs. current GitHub version")
print("=" * 70)
r = subprocess.run(["git", "diff", "LIMITATIONS.md"], cwd=REPO, capture_output=True, text=True)
if r.stdout:
    print(r.stdout)
else:
    print("(no changes — file already matches this template)")

# --- 5) Print FULL content for copy-paste ---
print("\n" + "=" * 70)
print("FULL FINAL CONTENT — copy everything below this line")
print("=" * 70)
print(FINAL_CONTENT)
print("=" * 70)
print("END OF FILE")
print("=" * 70)

print("\nNEXT STEP:")
print("1. Copy the content between the two '=' lines above.")
print("2. Open: https://github.com/Hasti-Audit/Hasti-Audit/edit/main/LIMITATIONS.md")
print("3. Select all (Ctrl+A / Cmd+A), delete, paste the new content.")
print("4. Commit with message: 'docs: rebuild LIMITATIONS.md (fix duplicate NC-B3, anonymize note)'")

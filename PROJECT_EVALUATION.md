# Project Evaluation Form – Hasti Audit

1. **Project name / Repository:**
   Client-Side Scanner Test (Internal Validation)

2. **Date of scan:**
   2026-10-27

3. **Tool used (exact version):**
   Hasti Client-Side Scanner v1.0

4. **Scope (what was scanned?):**
   Static analysis of Python files in the local directory (`./test_file.py` and sample bundles).

5. **Total Python files scanned:**
   5

6. **Total findings:**
   - Critical: 8
   - High: 4
   - Medium: 0

7. **Confirmed vulnerability claimed? (Yes / No):**
   No (Static indicators only)

8. **Were limitations clearly stated in the report? (Yes / No):**
   Yes

9. **Sample findings (3–5 items max):**
   - **File:** `./test_file.py`
     **Line:** 3
     **Issue ID / Type:** NC-B1
     **Short description:** Unsafe use of `pickle.load`.
     **Why this matters:** `pickle` deserialization can lead to Arbitrary Code Execution (ACE) if the file is tampered with.
     
   - **File:** `./ultralytics/data/utils.py`
     **Line:** 828
     **Issue ID / Type:** NC-DANGEROUS
     **Short description:** Use of `exec()` detected.
     **Why this matters:** `exec()` allows dynamic execution of strings as Python code, creating a massive backdoor risk.
     
   - **File:** `./ultralytics/nn/tasks.py`
     **Line:** 2101
     **Issue ID / Type:** NC-DANGEROUS
     **Short description:** Use of `eval()` detected.
     **Why this matters:** `eval()` can execute malicious expressions, compromising system integrity.

10. **False positives estimated by you (% or description):**
    Low (< 5%). The scanner uses AST (Abstract Syntax Tree) parsing, which accurately detects function calls without being fooled by comments or string literals.

11. **Final report tone:**
    Cautious / Neutral (Technical indicators only, no definitive claims)

12. **Link to report file or paste of Summary section:**
    The output is a generated Markdown report (`report.md`) containing all file paths and line numbers.

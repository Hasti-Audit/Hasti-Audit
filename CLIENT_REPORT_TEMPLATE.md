# Hasti Audit — Technical Pre-Check Report

**Client:** [Client name]  
**Engagement:** Tier 1 Static Code Screening  
**Date:** [YYYY-MM-DD]  
**Tool:** Hasti AI Audit v12  
**Auditor:** Ahmad Sabawoon Rasoli  
**Report ID:** [e.g. HASTI-2026-001]

---

## 1. Executive summary

This report presents the results of a **scoped static pre-check** on selected Python files provided by the client (or produced via the client-side scanner).

| Metric | Value |
|--------|-------|
| Files reviewed | [N] |
| Total findings | [N] |
| High | [N] |
| Medium | [N] |

**Overall assessment:** [No high findings / Findings require review / Priority review recommended]

This is a technical pre-check only. It is **not** a full security audit, **not** penetration testing, and **not** a legal or EU AI Act certification.

---

## 2. Scope

**In scope**
- Static detection of selected high-risk patterns in Python source:
  - unsafe deserialization (`pickle`, `torch.load` without `weights_only=True`)
  - dangerous calls (`eval`/`exec`, `os.system`/`popen`, `subprocess` with `shell=True`)
  - unsafe `yaml.load` (without `SafeLoader`)
  - basic dynamic SQL construction in `execute()`
  - simple data-leakage indicators (`fit`/`fit_transform` on names like `X`/`df`/`data`)
  - simple hardcoded secret heuristics (e.g. `sk_live_`, AWS key-shaped assignments)

**Out of scope**
- Runtime exploit verification
- Non-Python code, infrastructure, cloud IAM, network security
- Model quality, bias, clinical/financial correctness
- Legal compliance determination (EU AI Act, MDR, etc.)

**Process used**
- [ ] Client-side scanner (`report.md` only; source remained with client)
- [ ] Files shared under agreed confidentiality

---

## 3. Findings

| ID | Severity | File | Line | Issue | Notes for client |
|----|----------|------|------|-------|------------------|
| NC-… | HIGH/MEDIUM | path | n | short message | e.g. review if test-only / replace with safe API |

If none:

> No issues matching the current rule set were found in the reviewed files.

---

## 4. Interpretation guidance

- **High** findings should be reviewed before production use of the affected path.
- Findings in **tests**, **examples**, or **docs** may be intentional; confirm context.
- Absence of findings does **not** mean the system is secure.

---

## 5. Recommendations

1. [Most important technical action]
2. [Second action]
3. Re-run this pre-check after major changes to model loading, data pipelines, or query construction.

---

## 6. Claim boundary

**This report may support:** internal engineering discussion about specific static patterns.  

**This report does not establish:** regulatory compliance, certification, absence of vulnerabilities, or fitness for clinical/financial deployment.

---

## 7. Next optional steps

- Manual review of selected findings (Tier 2-style human interpretation)
- Broader file set or second pass after remediation
- Separate arithmetic/tool-use reliability check only if relevant to the product

---

*Hasti Audit — independent technical pre-check*  
*Contact: Sabawoon.rasoli@gmail.com*

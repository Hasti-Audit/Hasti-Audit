# Hasti Audit — Limitations

**Last updated:** 2026-11-02  
**Applies to:** Hasti AI Audit v12 / Client Scanner v12r

## What Hasti does

Hasti performs a **scoped static pre-check** on Python source code. It looks for selected high-risk patterns commonly relevant to AI/data systems (unsafe deserialization, dangerous dynamic execution, unsafe YAML loading, basic dynamic SQL construction, simple leakage indicators, and simple secret-looking assignments).

## What Hasti does not do

- Does not prove that code is safe or secure
- Does not replace a full security audit, penetration test, or code review by a qualified team
- Does not provide legal advice or EU AI Act / MDR / ISO certification
- Does not analyze non-Python components, deployed infrastructure, or runtime behavior by default
- Does not guarantee detection of obfuscated, generated, or multi-stage vulnerable flows
- Does not validate model accuracy, fairness, clinical correctness, or business logic

## About findings

- Findings are **technical indicators** for human review
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

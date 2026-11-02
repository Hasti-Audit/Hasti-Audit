# Hasti AI Audit - Sample Report

**Target:** Simulated FinTech Codebase (Mock)
**Tool:** Hasti v12 (Client Scanner)
**Date:** 2026-11-02

## Summary

| Metric | Value |
|--------|-------|
| Files scanned | 10 |
| Total findings | 10 |
| High | 9 |
| Medium | 1 |

## Detailed Findings

| ID | Severity | File | Line | Issue |
|----|----------|------|------|-------|
| NC-B1 | HIGH | `tier1_static/data_loader.py` | 3 | Unsafe pickle load |
| NC-SQL | HIGH | `tier1_static/query_builder.py` | 5 | Dynamic SQL in execute() |
| NC-SHELL | HIGH | `tier1_static/ops_runner.py` | 3 | subprocess with shell=True |
| NC-YAML | HIGH | `tier3_edge/nested_yaml_loader.py` | 4 | yaml.load without SafeLoader |
| NC-TORCH | HIGH | `tier3_edge/deep_learning_loader.py` | 3 | torch.load without weights_only |
| NC-SECRET | HIGH | `tier2_hardcoded/aws_s3_sync.py` | 1 | Hardcoded AWS Key |
| NC-B3 | MEDIUM | `tier2_hardcoded/ml_pipeline_leak.py` | 4 | fit_transform on full X |

## Limitations

This is a scoped static pre-check only. Findings are technical indicators for human review, not confirmed vulnerabilities or legal certifications. See [LIMITATIONS.md](../LIMITATIONS.md) for details.

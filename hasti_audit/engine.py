from __future__ import annotations
import ast
from typing import List
from .models import Finding, findings_to_legacy
from .context import AnalysisContext
from .registry import RuleRegistry, registry
from .rules.deserialization import DeserializationRule
from .rules.command_exec import CommandExecRule
from .rules.dynamic_exec import DynamicExecRule
from .rules.sql_injection import SqlInjectionRule
from .rules.hardcoded_secrets import HardcodedSecretsRule
from .rules.ml_leakage import MlLeakageRule

def _register_defaults(reg: RuleRegistry):
    reg.register(DeserializationRule())
    reg.register(CommandExecRule())
    reg.register(DynamicExecRule())
    reg.register(SqlInjectionRule())
    reg.register(HardcodedSecretsRule())
    reg.register(MlLeakageRule())

_register_defaults(registry)

def audit_source(code: str, filename: str = "file.py") -> List[dict]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError) as e:
        return [{"id": "NC-PARSE", "severity": "INFO", "line": getattr(e, "lineno", None) or 0,
                 "message": "could not parse file; it was NOT scanned", "file": filename}]
    ctx = AnalysisContext(tree, filename, source=code)
    findings: List[Finding] = []
    for rule in registry.all_rules():
        findings.extend(rule.apply(ctx, tree, filename))
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: (f.line or 0, f.rule_id)):
        key = (f.rule_id, f.line, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return findings_to_legacy(out)

def scan_file(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return audit_source(f.read(), filename=path)

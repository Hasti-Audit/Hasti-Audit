from __future__ import annotations
import ast
from .base import make_finding

class DynamicExecRule:
    rule_id = "NC-DYN"

    def apply(self, context, tree, filename):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                findings.append(make_finding("NC-DYN", "HIGH", f"{node.func.id}()", filename, getattr(node, "lineno", None)))
        return findings

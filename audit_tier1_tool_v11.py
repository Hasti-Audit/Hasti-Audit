# ============================================================
# Hasti AI Audit - Core Static Scanner (v11 Fixed)
# ============================================================
# This is the actual static analysis tool. It does NOT download 
# any external code or run in a loop.

import os
import ast
import re
from typing import List, Dict
from pathlib import Path

class Tier1Auditor:
    def __init__(self):
        self.findings: List[Dict] = []
        self.filename: str = "code.py"

    def audit_code(self, code: str, filename: str = "submitted_code.py") -> List[Dict]:
        self.findings = []
        self.filename = filename
        try:
            tree = ast.parse(code)
            self._check_pickle_usage(tree)
            self._check_data_leakage(tree)
            self._check_dangerous_calls(tree)
            self._check_unsafe_yaml(tree)
        except SyntaxError as e:
            self.findings.append({"id": "PARSE_ERROR", "severity": "HIGH", "message": f"Syntax Error: {str(e)}", "line": getattr(e, "lineno", None)})
        self._regex_checks(code)
        return self.findings

    def audit_file(self, filepath: str) -> List[Dict]:
        path = Path(filepath)
        if not path.exists(): return []
        try:
            code = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        return self.audit_code(code, filename=str(path))

    def _check_pickle_usage(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" and node.func.attr in ("load", "loads")):
                    self.findings.append({"id": "NC-B1", "severity": "CRITICAL", "message": f"Unsafe use of pickle.{node.func.attr}().", "line": node.lineno, "recommendation": "Avoid pickle for untrusted data."})

    def _check_data_leakage(self, tree: ast.AST):
        full_data_names = {"X", "df", "data", "dataset", "features", "X_full", "X_all"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("fit", "fit_transform") and node.args:
                    arg = node.args[0]
                    arg_name = arg.id if isinstance(arg, ast.Name) else (arg.attr if isinstance(arg, ast.Attribute) else None)
                    if arg_name in full_data_names:
                        self.findings.append({"id": "NC-B3", "severity": "HIGH", "message": f"Possible data leakage: .{node.func.attr}() on full dataset ('{arg_name}').", "line": node.lineno, "recommendation": "Split data first."})

    def _check_dangerous_calls(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self.findings.append({"id": "NC-DANGEROUS", "severity": "CRITICAL", "message": f"Use of {node.func.id}().", "line": node.lineno, "recommendation": "Avoid eval/exec."})
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in ("system", "popen"):
                    self.findings.append({"id": "NC-DANGEROUS", "severity": "CRITICAL", "message": f"Use of os.{node.func.attr}().", "line": node.lineno, "recommendation": "Prefer subprocess with shell=False."})

    def _check_unsafe_yaml(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml" and node.func.attr == "load":
                    if not any(kw.arg == "Loader" for kw in node.keywords):
                        self.findings.append({"id": "NC-YAML", "severity": "CRITICAL", "message": "Unsafe yaml.load().", "line": node.lineno, "recommendation": "Use yaml.safe_load()."})

    def _regex_checks(self, code: str):
        for i, line in enumerate(code.splitlines(), 1):
            if re.search(r"pickle\.(load|loads)\s*\(", line):
                if not any(f.get("line") == i and f["id"] == "NC-B1" for f in self.findings):
                    self.findings.append({"id": "NC-B1", "severity": "CRITICAL", "message": "Unsafe pickle usage.", "line": i, "recommendation": "Replace with safer serialization."})

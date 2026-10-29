import ast
import re
import os
import json
from pathlib import Path
from typing import List, Dict, Tuple, Set

class Tier1Auditor:
    def __init__(self):
        self.findings: List[Dict] = []
        self.filename: str = "code.py"

    def audit_code(self, code: str, filename: str = "submitted_code.py") -> List[Dict]:
        self.findings = []
        self.filename = filename
        try:
            tree = ast.parse(code)
            aliases = self._get_aliases(tree)
            self._check_pickle(tree, aliases)
            self._check_sql_injection(tree)
            self._check_unsafe_yaml(tree)
        except SyntaxError as e:
            self.findings.append({"id": "PARSE_ERROR", "severity": "HIGH", "message": f"Syntax Error: {str(e)}", "line": getattr(e, "lineno", None)})
        return self.findings

    def _get_aliases(self, tree: ast.AST) -> Dict[str, str]:
        """Tracks import aliases to find obfuscated calls (e.g., import pickle as pk)."""
        al = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom):
                for a in n.names:
                    al[a.asname or a.name] = f"{n.module or ''}.{a.name}"
            elif isinstance(n, ast.Import):
                for a in n.names:
                    al[a.asname or a.name.split(".")[0]] = a.name
        return al

    def _check_pickle(self, tree: ast.AST, aliases: Dict[str, str]):
        """NC-B1: Advanced detection of pickle/joblib/torch loading."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                module = None
                
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        module = aliases.get(node.func.value.id, node.func.value.id)
                        func_name = node.func.attr
                elif isinstance(node.func, ast.Name) and node.func.id in aliases:
                    module, _, func_name = aliases[node.func.id].rpartition(".")
                    module = module.split(".")[0]

                if func_name in ("load", "loads"):
                    if module in ("pickle", "joblib", "torch", "yaml"):
                        severity = "CRITICAL" if module in ("pickle", "joblib") else "HIGH"
                        # Special case for torch: check weights_only
                        if module == "torch":
                            has_weights_only = any(kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                            severity = "LOW" if has_weights_only else "MEDIUM"
                        
                        # Special case for yaml: check safe Loader
                        if module == "yaml":
                            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                            if has_loader: continue # Skip if safe loader is used
                            severity = "CRITICAL"

                        self.findings.append({
                            "id": "NC-B1",
                            "severity": severity,
                            "message": f"Unsafe use of {module}.{func_name}().",
                            "line": node.lineno,
                            "recommendation": f"Replace {module} with a safe deserialization method."
                        })

    def _check_sql_injection(self, tree: ast.AST):
        """NC-B4: Detects SQL injection risks (f-strings or concatenation in execute)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                if node.args:
                    arg = node.args[0]
                    # Check for f-strings or string concatenation
                    if isinstance(arg, ast.JoinedStr) or (isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod))):
                        self.findings.append({
                            "id": "NC-B4",
                            "severity": "HIGH",
                            "message": "Potential SQL Injection: Dynamic string formatting in execute().",
                            "line": node.lineno,
                            "recommendation": "Use parameterized queries (e.g., cursor.execute('... WHERE id = ?', (id,)))."
                        })

    def _check_unsafe_yaml(self, tree: ast.AST):
        """Fallback for yaml.load() if not caught by alias logic."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in ("yaml", "yml") and node.func.attr == "load":
                    if not any(kw.arg == "Loader" for kw in node.keywords):
                        self.findings.append({"id": "NC-YAML", "severity": "CRITICAL", "message": "Unsafe yaml.load().", "line": node.lineno, "recommendation": "Use yaml.safe_load()."})

# ============================================================
# Test Suite (from your prompt)
# ============================================================
if __name__ == "__main__":
    test_cases = [
        ("import pickle\nm = pickle.load(open('a','rb'))", "pickle.load"),
        ("import joblib as jl\nm = jl.load('a.pkl')", "joblib alias"),
        ("from pickle import load\nm = load(open('a','rb'))", "from-import load"),
        ("import torch\nm = torch.load('a.pt')", "torch default"),
        ("import torch\nm = torch.load('a.pt', weights_only=True)", "torch safe"),
        ("def f(cur, t):\n    cur.execute(f\"SELECT * FROM {t}\")", "sql injection f-string"),
        ("def f(cur, n):\n    cur.execute('SELECT * FROM u WHERE name = ' + n)", "sql injection concat"),
    ]
    
    print("=" * 60)
    print("TESTING ADVANCED V11 SCANNER")
    print("=" * 60)
    
    for code, desc in test_cases:
        print(f"\n--- Testing: {desc} ---")
        auditor = Tier1Auditor()
        findings = auditor.audit_code(code)
        if not findings:
            print("✅ Clean (No issues found)")
        else:
            for f in findings:
                print(f"[{f['severity']}] {f['id']} (Line {f['line']}): {f['message']}")

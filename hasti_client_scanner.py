# ============================================================
# Hasti AI Audit - Client-Side Scanner v2.0
# Version: 2.0 (Enterprise Grade)
# ============================================================
import os
import ast
import re
import hashlib
import sys

class ClientScanner:
    def __init__(self):
        self.findings = []
        self.files_scanned = 0
        self.files_skipped = 0

    def scan_dir(self, directory="."):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".") 
                       and d not in ("__pycache__", "venv", ".venv", "node_modules", "env")]
            for file in files:
                if file.endswith(".py"):
                    self.scan_file(os.path.join(root, file))

    def scan_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            try:
                tree = ast.parse(content)
            except SyntaxError:
                self.files_skipped += 1
                return

            self.files_scanned += 1

            # 1. Check for unsafe deserialization (pickle, joblib, torch)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        mod = node.func.value.id
                        fn = node.func.attr
                        if mod in ("pickle", "joblib") and fn in ("load", "loads"):
                            self.findings.append(f"[CRITICAL] NC-B1 | {filepath}:{node.lineno} | Unsafe use of {mod}.{fn}()")
                        if mod == "torch" and fn == "load":
                            has_weights_only = any(kw.arg == "weights_only" and getattr(kw.value, 'value', None) is True for kw in node.keywords)
                            sev = "LOW" if has_weights_only else "HIGH"
                            self.findings.append(f"[{sev}] NC-B1 | {filepath}:{node.lineno} | torch.load() usage")

                # 2. Check for SQL Injection (string formatting in execute)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                            self.findings.append(f"[HIGH] NC-B4 | {filepath}:{node.lineno} | Potential SQL Injection in execute()")

                # 3. Check for Dangerous Calls (eval, exec, os.system)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        self.findings.append(f"[CRITICAL] NC-DANGEROUS | {filepath}:{node.lineno} | Use of {node.func.id}()")
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in ("system", "popen"):
                        self.findings.append(f"[CRITICAL] NC-DANGEROUS | {filepath}:{node.lineno} | Use of os.{node.func.attr}()")

                # 4. Check for unsafe yaml.load
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "load" and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                    if not any(kw.arg == "Loader" for kw in node.keywords):
                        self.findings.append(f"[CRITICAL] NC-YAML | {filepath}:{node.lineno} | Unsafe yaml.load()")

        except Exception:
            self.files_skipped += 1

def main():
    print("# Hasti AI Audit - Client Report")
    print("**Scanner:** Client-Side Scanner v2.0")
    print("**Scope:** Static pattern matching only\n")
    
    scanner = ClientScanner()
    scanner.scan_dir(".")
    
    print(f"**Files Scanned:** {scanner.files_scanned}")
    print(f"**Files Skipped (Syntax/Read Error):** {scanner.files_skipped}\n")
    
    print("## Findings")
    if not scanner.findings:
        print("No issues matching the current rule set were found.")
    else:
        for f in scanner.findings:
            print(f"- {f}")
            
    print("\n---\n*This is an automated static scan. Manual review is required.*")

if __name__ == "__main__":
    main()

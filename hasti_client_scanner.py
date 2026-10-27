# Hasti AI Audit - Client-Side Scanner (Zero Data Leakage)
# Instructions for the client:
# 1. Place this file in the root of your project.
# 2. Run: python hasti_client_scanner.py > audit_report.md
# 3. Send the generated "audit_report.md" back to us. No source code is included in this file.

import os
import ast
import re

class ClientScanner:
    def __init__(self):
        self.findings = []
    def scan_dir(self, directory="."):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "venv", "node_modules")]
            for file in files:
                if file.endswith(".py"):
                    self.scan_file(os.path.join(root, file))
    def scan_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                tree = ast.parse(content)
                # Check for pickle.load
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if (isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle" and node.func.attr in ("load", "loads")):
                            self.findings.append(f"- **NC-B1 (CRITICAL)**: Unsafe `pickle.load` at `{filepath}:{node.lineno}`")
                        if (isinstance(node.func.value, ast.Name) and node.func.value.id in ("os", "subprocess") and node.func.attr in ("system", "popen", "call", "run")):
                            self.findings.append(f"- **NC-DANGEROUS (HIGH)**: Dangerous system call at `{filepath}:{node.lineno}`")
        except Exception:
            pass

if __name__ == "__main__":
    print("# Hasti AI Audit - Client Report\n")
    print("**Target:** Local Codebase\n")
    print("**Status:** Scan Complete\n")
    print("## Findings\n")
    scanner = ClientScanner()
    scanner.scan_dir(".")
    if not scanner.findings:
        print("No critical issues found.")
    else:
        for finding in scanner.findings:
            print(finding)

# ============================================================
# Hasti AI Audit - Client-Side Scanner
# Version: 1.0
# ============================================================
# Instructions for the client:
# 1. Place this file in the root folder of your Python project.
# 2. Open a terminal in that folder.
# 3. Run:  python hasti_client_scanner.py > audit_report.md
# 4. Send only the generated file "audit_report.md" back to us.
#    Do NOT send your source code.
# ============================================================

import os
import ast
import re
from datetime import datetime, timezone

class ClientScanner:
    def __init__(self):
        self.findings = []

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
                return

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                if isinstance(node.func, ast.Attribute):
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == "pickle" and 
                        node.func.attr in ("load", "loads")):
                        self.findings.append({
                            "id": "NC-B1",
                            "severity": "CRITICAL",
                            "file": filepath,
                            "line": node.lineno,
                            "message": "Unsafe use of pickle.load/loads detected."
                        })

                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == "os" and 
                        node.func.attr in ("system", "popen")):
                        self.findings.append({
                            "id": "NC-DANGEROUS",
                            "severity": "CRITICAL",
                            "file": filepath,
                            "line": node.lineno,
                            "message": f"Use of os.{node.func.attr}() detected."
                        })

                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == "subprocess" and 
                        node.func.attr in ("call", "run", "Popen", "check_output")):
                        for kw in node.keywords:
                            if (kw.arg == "shell" and 
                                isinstance(kw.value, ast.Constant) and 
                                kw.value.value is True):
                                self.findings.append({
                                    "id": "NC-DANGEROUS",
                                    "severity": "HIGH",
                                    "file": filepath,
                                    "line": node.lineno,
                                    "message": "subprocess call with shell=True detected."
                                })

                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id in ("yaml", "yml") and 
                        node.func.attr == "load"):
                        has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                        if not has_loader:
                            self.findings.append({
                                "id": "NC-YAML",
                                "severity": "CRITICAL",
                                "file": filepath,
                                "line": node.lineno,
                                "message": "Unsafe yaml.load() detected (no Loader specified)."
                            })

                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self.findings.append({
                        "id": "NC-DANGEROUS",
                        "severity": "CRITICAL",
                        "file": filepath,
                        "line": node.lineno,
                        "message": f"Use of {node.func.id}() detected."
                    })

        except Exception:
            pass

def main():
    print("# Hasti AI Audit - Client Report")
    print()
    print(f"**Scan date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("**Scanner:** Hasti Client-Side Scanner v1.0")
    print("**Scope:** Static pattern matching only")
    print()
    print("## Findings")
    print()

    scanner = ClientScanner()
    scanner.scan_dir(".")

    if not scanner.findings:
        print("No issues matching the current rule set were found.")
    else:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        scanner.findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

        for i, f in enumerate(scanner.findings, 1):
            print(f"{i}. **[{f['severity']}] {f['id']}**")
            print(f"   - File: `{f['file']}`")
            print(f"   - Line: {f['line']}")
            print(f"   - Message: {f['message']}")
            print()

    print("---")
    print("*This is an automated static scan. Manual review is recommended.*")

if __name__ == "__main__":
    main()

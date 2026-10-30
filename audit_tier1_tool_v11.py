import ast
import re
from pathlib import Path

# ============================================================
# Hasti AI Audit v11 - Final Validation (Fixing Missed Cases)
# ============================================================

def audit_source(code, filename="file.py"):
    findings = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    # پیدا کردن Aliasها
    aliases = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            for a in n.names:
                aliases[a.asname or a.name] = f"{n.module or ''}.{a.name}"
        elif isinstance(n, ast.Import):
            for a in n.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name

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

            # NC-B1: Unsafe Deserialization
            if func_name in ("load", "loads") and module in ("pickle", "joblib"):
                findings.append({"severity": "HIGH", "id": "NC-B1", "message": f"Unsafe {module}.{func_name}()", "line": node.lineno})
            if func_name == "load" and module == "torch":
                has_weights_only = any(kw.arg == "weights_only" and getattr(kw.value, 'value', None) is True for kw in node.keywords)
                sev = "LOW" if has_weights_only else "HIGH"
                findings.append({"severity": sev, "id": "NC-B1", "message": "torch.load()", "line": node.lineno})

            # NC-B4: SQL Injection (F-string, .format و +)
            if func_name == "execute" and node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    findings.append({"severity": "HIGH", "id": "NC-B4", "message": "Potential SQL Injection", "line": node.lineno})
                # تشخیص .format()
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    findings.append({"severity": "HIGH", "id": "NC-B4", "message": "Potential SQL Injection via .format()", "line": node.lineno})

            # NC-DANGEROUS: eval, exec, os.system
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                findings.append({"severity": "HIGH", "id": "NC-DANGEROUS", "message": f"Use of {node.func.id}()", "line": node.lineno})
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in ("system", "popen"):
                findings.append({"severity": "HIGH", "id": "NC-DANGEROUS", "message": f"Use of os.{node.func.attr}()", "line": node.lineno})

            # NC-YAML: Unsafe yaml.load
            if func_name == "load" and module == "yaml":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        # اگر Loader برابر yaml.SafeLoader باشد، امن است
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr in ("SafeLoader", "CSafeLoader", "FullLoader"):
                            has_safe_loader = True
                if not has_safe_loader:
                    findings.append({"severity": "HIGH", "id": "NC-YAML", "message": "Unsafe yaml.load() (missing or unsafe Loader)", "line": node.lineno})

    return findings

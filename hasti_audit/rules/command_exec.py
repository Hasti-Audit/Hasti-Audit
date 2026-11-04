from __future__ import annotations
import ast
from .base import make_finding
from ..context import const_true

SUBPROC_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}

class CommandExecRule:
    rule_id = "NC-SHELL"

    def apply(self, context, tree, filename):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call): continue
            ref = context.resolve_ref(node.func)
            if not ref: continue
            mod, name = ref
            line = getattr(node, "lineno", None)
            if mod == "subprocess" and name in SUBPROC_FUNCS:
                if any(kw.arg == "shell" and const_true(kw.value) for kw in node.keywords):
                    findings.append(make_finding("NC-SHELL", "HIGH", "subprocess with shell=True", filename, line))
            elif mod == "os" and name in {"system", "popen"}:
                dynamic = bool(node.args) and not isinstance(node.args[0], ast.Constant)
                sev = "HIGH" if dynamic else "MEDIUM"
                findings.append(make_finding("NC-SHELL", sev, f"os.{name}() runs a shell command", filename, line))
        return findings

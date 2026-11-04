from __future__ import annotations
import ast
from .base import make_finding
from ..context import is_dynamic_string

SQL_SINKS = {"execute", "executemany", "executescript", "exec_driver_sql", "read_sql", "read_sql_query"}

class SqlInjectionRule:
    rule_id = "NC-SQL"

    def apply(self, context, tree, filename):
        findings = []
        for scope in context.iter_scopes():
            tainted = context.build_scope_taint(scope)
            nodes = sorted((n for n in ast.walk(scope) if hasattr(n, "lineno")), key=lambda n: (n.lineno or 0, getattr(n, "col_offset", 0) or 0))
            for n in nodes:
                if not isinstance(n, ast.Call) or not n.args: continue
                f = n.func
                sink = (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)) in SQL_SINKS
                a0 = n.args[0]
                if sink and (is_dynamic_string(a0) or (isinstance(a0, ast.Name) and tainted.get(a0.id))):
                    findings.append(make_finding("NC-SQL", "HIGH", "dynamic SQL (built with f-string/format/%/+)", filename, n.lineno))
        return findings

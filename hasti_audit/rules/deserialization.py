from __future__ import annotations
import ast
from .base import make_finding
from ..context import const_true, is_safe_yaml_loader

PICKLE_MODULES = {"pickle", "_pickle", "dill", "cloudpickle"}

class DeserializationRule:
    rule_id = "NC-B1"

    def apply(self, context, tree, filename):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call): continue
            ref = context.resolve_ref(node.func)
            if not ref: continue
            mod, name = ref
            line = getattr(node, "lineno", None)
            if mod in PICKLE_MODULES and name in {"load", "loads"}:
                findings.append(make_finding("NC-B1", "HIGH", f"Unsafe {mod}.{name} (deserialization can execute code)", filename, line))
            elif mod == "joblib" and name == "load":
                findings.append(make_finding("NC-B1", "HIGH", "Unsafe joblib.load (pickle-based deserialization)", filename, line))
            elif mod == "torch" and name == "load":
                if not any(kw.arg == "weights_only" and const_true(kw.value) for kw in node.keywords):
                    findings.append(make_finding("NC-TORCH", "HIGH", "torch.load without weights_only=True", filename, line))
            elif mod == "yaml" and name in {"load", "load_all", "unsafe_load", "unsafe_load_all"}:
                if name.startswith("unsafe") or not is_safe_yaml_loader(node):
                    findings.append(make_finding("NC-YAML", "HIGH", f"yaml.{name} without SafeLoader", filename, line))
        return findings

from __future__ import annotations
import ast
from typing import Dict, Iterator, List, Optional, Tuple

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

class ImportTracker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.module_aliases: Dict[str, str] = {}
        self.name_aliases: Dict[str, Tuple[str, str]] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            root = alias.name.split(".")[0]
            self.module_aliases[local] = root
            self.module_aliases[alias.name] = root

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module:
            return
        root = node.module.split(".")[0]
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.name_aliases[local] = (root, alias.name)

def const_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True

def fold_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = fold_str(node.left), fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None

def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return fold_str(node) is None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return bool(node.args or node.keywords)
    return False

def scope_nodes(scope: ast.AST) -> List[ast.AST]:
    out: List[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        out.append(n)
        if not isinstance(n, _SCOPES):
            stack.extend(ast.iter_child_nodes(n))
    return out

def is_safe_yaml_loader(call: ast.Call) -> bool:
    loader = None
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    name = loader.attr if isinstance(loader, ast.Attribute) else getattr(loader, "id", "") or ""
    return "SafeLoader" in str(name)

def key_of(target: ast.AST) -> Optional[str]:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        sl = target.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
    return None

def name_value_pairs(tree: ast.AST) -> Iterator[Tuple[Optional[str], ast.AST]]:
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                yield key_of(t), n.value
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            yield key_of(n.target), n.value
        elif isinstance(n, ast.keyword) and n.arg:
            yield n.arg, n.value
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    yield k.value, v
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            pos = a.args[len(a.args) - len(a.defaults):] if a.defaults else []
            for arg, d in list(zip(pos, a.defaults)) + [(x, d) for x, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]:
                yield arg.arg, d

class AnalysisContext:
    def __init__(self, tree: ast.AST, filename: str, source: str = "") -> None:
        self.tree = tree
        self.filename = filename
        self.source = source
        self.tracker = ImportTracker()
        self.tracker.visit(tree)
        self.var_alias: Dict[str, Tuple[str, str]] = {}
        self._build_var_aliases()

    def _build_var_aliases(self) -> None:
        for _ in range(2):
            for n in ast.walk(self.tree):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    ref = self.resolve_ref(n.value)
                    if ref:
                        self.var_alias[n.targets[0].id] = ref

    def resolve_ref(self, n: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            return self.tracker.module_aliases.get(n.value.id, n.value.id), n.attr
        if isinstance(n, ast.Name):
            return self.tracker.name_aliases.get(n.id) or self.var_alias.get(n.id)
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr"
                and len(n.args) >= 2 and isinstance(n.args[0], ast.Name)
                and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)):
            return self.tracker.module_aliases.get(n.args[0].id, n.args[0].id), n.args[1].value
        return None

    def iter_scopes(self) -> List[ast.AST]:
        return [self.tree] + [n for n in ast.walk(self.tree) if isinstance(n, _SCOPES)]

    def build_scope_taint(self, scope: ast.AST) -> Dict[str, bool]:
        tainted: Dict[str, bool] = {}
        nodes = sorted((n for n in scope_nodes(scope) if hasattr(n, "lineno")),
                       key=lambda n: (n.lineno or 0, getattr(n, "col_offset", 0) or 0))
        for n in nodes:
            if isinstance(n, ast.Assign):
                dyn = is_dynamic_string(n.value)
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted[t.id] = dyn
            elif isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) and isinstance(n.target, ast.Name):
                if fold_str(n.value) is None:
                    tainted[n.target.id] = True
        return tainted

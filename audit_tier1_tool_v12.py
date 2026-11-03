import ast
import os
import re
from typing import Dict, List, Optional, Tuple


class ImportTracker(ast.NodeVisitor):
    def __init__(self):
        self.module_aliases: Dict[str, str] = {}
        self.name_aliases: Dict[str, Tuple[str, str]] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name
            root = alias.name.split(".")[0]
            self.module_aliases[local] = root
            self.module_aliases[alias.name] = root

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if not node.module:
            return
        root = node.module.split(".")[0]
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.name_aliases[local] = (root, alias.name)


# ------------------------------------------------------------------ constants
PICKLE_MODULES = {"pickle", "_pickle", "dill", "cloudpickle"}
SUBPROC_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}
SQL_SINKS = {"execute", "executemany", "executescript", "exec_driver_sql", "read_sql", "read_sql_query"}
SCALER_CLASSES = {"StandardScaler", "MinMaxScaler", "RobustScaler", "MaxAbsScaler", "Normalizer", "PowerTransformer",
                  "QuantileTransformer", "SimpleImputer", "KNNImputer", "IterativeImputer", "PCA", "TruncatedSVD",
                  "OneHotEncoder", "OrdinalEncoder", "LabelEncoder", "TfidfVectorizer", "CountVectorizer"}
SCALER_NAME_HINT = re.compile(r"(scaler|transformer|encoder|imputer|vectorizer|pca|normalizer)", re.I)
FULL_DATA_NAMES = {"x", "df", "data", "dataset", "features", "full"}
TARGET_COLS = {"label", "target", "y", "default", "is_default", "defaulted", "churn", "fraud", "outcome",
               "sepsis", "readmitted", "clicked", "purchased", "converted"}
EVAL_WORDS = ("eval", "metric", "analy", "report", "plot", "backtest", "performance", "benchmark", "visual")
SECRET_NAME = re.compile(r"(password|passwd|pwd|secret|api_?key|access_?key|private_?key|aws_?key|"
                         r"(?:auth|access|api|bearer|refresh|session|client)_?token|credential)", re.I)
NAME_EXCLUDE = re.compile(r"(_env|_var|_name|_path|_file|_field|_length|_len|_url|_header|_label|_type|_min|_max|_policy|_hint|_pattern)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$.*|\{.*\}|%.*|x+|\*+|your[_ -].*|change_?me.*|none|null|todo|example|password|secret|token|test|dummy)$", re.I)
ENV_LIKE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")
URL_PW = re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s@]+)@", re.I)
SECRET_PATTERNS = [("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
                   ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}")),
                   ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
                   ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
                   ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"))]
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


# ------------------------------------------------------------------ helpers
def _const_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def _fold_str(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left), _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _is_dynamic(node) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _fold_str(node) is None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return bool(node.args or node.keywords)
    return False


def _scope_nodes(scope):
    out, stack = [], list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        out.append(n)
        if not isinstance(n, _SCOPES):
            stack.extend(ast.iter_child_nodes(n))
    return out


def _safe_loader(call) -> bool:
    loader = None
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    name = loader.attr if isinstance(loader, ast.Attribute) else getattr(loader, "id", "")
    return "SafeLoader" in name


def _key_of(t) -> Optional[str]:
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute):
        return t.attr
    if isinstance(t, ast.Subscript):
        sl = t.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
    return None


def _name_value_pairs(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                yield _key_of(t), n.value
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            yield _key_of(n.target), n.value
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


# ------------------------------------------------------------------ the audit
def audit_source(code: str, filename: str = "file.py") -> List[dict]:
    findings: List[dict] = []

    def add(fid, sev, line, msg):
        findings.append({"id": fid, "severity": sev, "line": line, "message": msg, "file": filename})

    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError) as e:
        return [{"id": "NC-PARSE", "severity": "INFO", "line": getattr(e, "lineno", None) or 0,
                 "message": "could not parse file; it was NOT scanned", "file": filename}]
    tracker = ImportTracker()
    tracker.visit(tree)
    var_alias: Dict[str, Tuple[str, str]] = {}

    def resolve_ref(n) -> Optional[Tuple[str, str]]:
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            return tracker.module_aliases.get(n.value.id, n.value.id), n.attr
        if isinstance(n, ast.Name):
            return tracker.name_aliases.get(n.id) or var_alias.get(n.id)
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" and len(n.args) >= 2
                and isinstance(n.args[0], ast.Name) and isinstance(n.args[1], ast.Constant)
                and isinstance(n.args[1].value, str)):
            return tracker.module_aliases.get(n.args[0].id, n.args[0].id), n.args[1].value
        return None

    for _ in range(2):
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                ref = resolve_ref(n.value)
                if ref:
                    var_alias[n.targets[0].id] = ref

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        line, func = getattr(node, "lineno", None), node.func
        ref = resolve_ref(func)
        if ref:
            mod, name = ref
            if mod in PICKLE_MODULES and name in {"load", "loads"}:
                add("NC-B1", "HIGH", line, "Unsafe %s.%s (deserialization can execute code)" % (mod, name))
            elif mod == "joblib" and name == "load":
                add("NC-B1", "HIGH", line, "Unsafe joblib.load (pickle-based deserialization)")
            elif mod == "torch" and name == "load":
                if not any(kw.arg == "weights_only" and _const_true(kw.value) for kw in node.keywords):
                    add("NC-TORCH", "HIGH", line, "torch.load without weights_only=True")
            elif mod == "subprocess" and name in SUBPROC_FUNCS:
                if any(kw.arg == "shell" and _const_true(kw.value) for kw in node.keywords):
                    add("NC-SHELL", "HIGH", line, "subprocess with shell=True")
            elif mod == "os" and name in {"system", "popen"}:
                dynamic = bool(node.args) and not isinstance(node.args[0], ast.Constant)
                add("NC-SHELL", "HIGH" if dynamic else "MEDIUM", line, "os.%s() runs a shell command" % name)
            elif mod == "yaml" and name in {"load", "load_all", "unsafe_load", "unsafe_load_all"}:
                if name.startswith("unsafe") or not _safe_loader(node):
                    add("NC-YAML", "HIGH", line, "yaml.%s without SafeLoader" % name)
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            add("NC-DYN", "HIGH", line, "%s()" % func.id)

    for scope in [tree] + [n for n in ast.walk(tree) if isinstance(n, _SCOPES)]:
        tainted: Dict[str, bool] = {}
        nodes = sorted((n for n in _scope_nodes(scope) if hasattr(n, "lineno")), key=lambda n: (n.lineno, n.col_offset))
        for n in nodes:
            if isinstance(n, ast.Assign):
                dyn = _is_dynamic(n.value)
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted[t.id] = dyn
            elif isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) and isinstance(n.target, ast.Name):
                if _fold_str(n.value) is None:
                    tainted[n.target.id] = True
            elif isinstance(n, ast.Call) and n.args:
                f = n.func
                sink = (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)) in SQL_SINKS
                a0 = n.args[0]
                if sink and (_is_dynamic(a0) or (isinstance(a0, ast.Name) and tainted.get(a0.id))):
                    add("NC-SQL", "HIGH", n.lineno, "dynamic SQL (built with f-string/format/%/+)")

    scaler_names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            c = n.value.func
            cname = c.attr if isinstance(c, ast.Attribute) else getattr(c, "id", None)
            if cname in SCALER_CLASSES:
                scaler_names.update(k for k in (_key_of(t) for t in n.targets) if k)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"fit", "fit_transform"}:
            r = node.func.value
            rname = r.func.attr if isinstance(r, ast.Call) and isinstance(r.func, ast.Attribute) else \
                getattr(r.func, "id", None) if isinstance(r, ast.Call) else _key_of(r)
            scaler_like = rname in SCALER_CLASSES or rname in scaler_names or bool(rname and SCALER_NAME_HINT.search(rname))
            if scaler_like and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.lower() in FULL_DATA_NAMES:
                add("NC-B3", "MEDIUM", node.lineno, "scaler/transformer fit on the full dataset; fit on the training split only")

    if not any(w in os.path.basename(filename).lower() for w in EVAL_WORDS):
        skip = set()
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(w in fn.name.lower() for w in EVAL_WORDS):
                skip.update(id(x) for x in ast.walk(fn))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "transform" and id(node) not in skip:
                chain = list(ast.walk(node.func.value))
                if any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "groupby" for c in chain) and \
                   any(isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.lower() in TARGET_COLS for c in chain):
                    add("NC-B3", "MEDIUM", node.lineno,
                        "target encoding via groupby/transform on a target column (leakage unless computed inside CV folds)")

    secret_lines: Dict[int, str] = {}
    for name, value in _name_value_pairs(tree):
        if name and SECRET_NAME.search(name) and not NAME_EXCLUDE.search(name):
            text = _fold_str(value)
            if text is not None and len(text.strip()) >= 4 and not PLACEHOLDER.match(text.strip()) and not ENV_LIKE.match(text.strip()):
                secret_lines.setdefault(value.lineno, "Hardcoded secret assigned to '%s'" % name)
    for n in ast.walk(tree):
        text = _fold_str(n) if isinstance(n, (ast.Constant, ast.BinOp)) else None
        if not text:
            continue
        for label, rx in SECRET_PATTERNS:
            if rx.search(text):
                secret_lines.setdefault(n.lineno, "Hardcoded %s" % label)
        m = URL_PW.search(text)
        if m and not PLACEHOLDER.match(m.group(1)):
            secret_lines.setdefault(n.lineno, "Connection string with an embedded password")
    for ln, msg in secret_lines.items():
        add("NC-SECRET", "HIGH", ln, msg)

    seen, out = set(), []
    for f in sorted(findings, key=lambda f: (f["line"] or 0, f["id"])):
        key = (f["id"], f["line"], f["message"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

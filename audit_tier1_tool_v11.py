"""Tier 1 Audit Tool v11 - static screening of Python code for ML/data risk patterns.

Rules (every finding has a line number and a severity HIGH / MEDIUM / LOW):
  NC-B1  model/artifact loaded (pickle, joblib, torch, ...) without integrity check
  NC-B3  data leakage (scaler/resampler fit before split, target-derived features)
  NC-B4  SQL built with f-string, .format(), % or + and then executed
  NC-B5  hardcoded credentials (secret-named literals incl. dict/kwarg/default
         values, known token formats, URLs with passwords)
  NC-B6  model saved (joblib.dump, torch.save, pickle.dump) without a checksum

Static AST analysis only. Standard library only. It never downloads anything,
never imports or executes the code it scans, and makes no network requests.
PASS means "no known pattern found", NOT "safe". Findings are technical
indicators, not a legal or compliance determination.

Command line:
  python audit_tier1_tool_v11.py /path/to/repo
  python audit_tier1_tool_v11.py app.py utils/ --flagged -o report.json --fail-on MEDIUM
Exit codes: 0 = nothing at/above --fail-on, 1 = findings at/above --fail-on,
            2 = usage error or path problem.

Python API:
  audit_source(text, name)  -> result for one source string
  audit_file(path)          -> result for one .py file
  run_audit_v11(path_or_dir_or_list) -> full report {"tool","summary","files"}
"""
import argparse
import ast
import json
import os
import re
import sys

TOOL = "audit_tier1_tool_v11"
SEV_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "site-packages", "__pycache__", "build", "dist"}

# ---------------------------------------------------------------- helpers
def _snip(lines, n):
    return lines[n - 1].strip()[:80] if 0 < n <= len(lines) else ""


def _aliases(tree):
    al = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            for a in n.names:
                al[a.asname or a.name] = "%s.%s" % (n.module or "", a.name)
        elif isinstance(n, ast.Import):
            for a in n.names:
                al[a.asname or a.name.split(".")[0]] = a.name
    return al


def _call_target(n, al):
    """(module, function) for pickle.load(..), pk.load(..), `from pickle import load`."""
    if not isinstance(n, ast.Call):
        return None
    f = n.func
    if isinstance(f, ast.Attribute):
        root = f
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            return al.get(root.id, root.id).split(".")[0], f.attr
    if isinstance(f, ast.Name) and f.id in al:
        mod, _, fn = al[f.id].rpartition(".")
        return mod.split(".")[0], fn
    return None


def _call_name(c):
    f = c.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)


def _recv_key(n):
    return n.id if isinstance(n, ast.Name) else (n.attr if isinstance(n, ast.Attribute) else None)


def _scope_walk(scope):
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, SCOPE_TYPES):
            stack.extend(ast.iter_child_nodes(n))


def _scopes(tree):
    return [(tree, "<module>")] + [(n, n.name) for n in ast.walk(tree) if isinstance(n, SCOPE_TYPES)]


def _idents(nodes):
    ids = set()
    for n in nodes:
        if isinstance(n, ast.Name):
            ids.add(n.id.lower())
        elif isinstance(n, ast.Attribute):
            ids.add(n.attr.lower())
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ids.add(n.name.lower())
        elif isinstance(n, ast.arg):
            ids.add(n.arg.lower())
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            ids.update(a.name.split(".")[-1].lower() for a in n.names)
    return ids


STRONG = ("sha256", "sha1", "sha512", "md5", "checksum", "manifest", "digest", "hmac", "hashlib")


def _has_strong(nodes):
    return any(w in i for i in _idents(nodes) for w in STRONG)


def _subscript_key(t):
    if not isinstance(t, ast.Subscript):
        return None
    sl = t.slice
    idx = getattr(ast, "Index", None)
    if idx is not None and isinstance(sl, idx):
        sl = sl.value
    return sl.value.lower() if isinstance(sl, ast.Constant) and isinstance(sl.value, str) else None


# ---------------------------------------------------------------- NC-B1 / NC-B6
LOAD_NAMES = {"load", "loads", "load_model"}
LOAD_MODULES = {"pickle", "joblib", "torch", "onnx", "mlflow", "keras", "tensorflow", "dill", "cloudpickle"}
CODE_EXEC_MODULES = {"pickle", "joblib", "dill", "cloudpickle"}   # loading can run arbitrary code
SAVE_FUNCS = {("joblib", "dump"), ("torch", "save"), ("pickle", "dump"), ("dill", "dump"), ("cloudpickle", "dump")}
WEAK_ACTIONS = ("validate", "verify", "schema", "check")
WEAK_TARGETS = ("model", "version", "shape", "sha", "hash", "checksum", "digest", "signature", "schema")


def _weak_check_near(tree, line, window=15):
    for n in ast.walk(tree):
        ln = getattr(n, "lineno", None)
        if ln is None or abs(ln - line) > window:
            continue
        if isinstance(n, ast.Assert):
            names = {x.id.lower() for x in ast.walk(n) if isinstance(x, ast.Name)}
            names |= {x.attr.lower() for x in ast.walk(n) if isinstance(x, ast.Attribute)}
            if any(t in x for x in names for t in WEAK_TARGETS):
                return True
        if isinstance(n, ast.Call):
            name = (_call_name(n) or "").lower()
            if any(a in name for a in WEAK_ACTIONS) and any(t in name for t in WEAK_TARGETS):
                return True
    return False


def check_loads(tree, lines):
    al, out = _aliases(tree), []
    file_strong = _has_strong(ast.walk(tree))
    for n in ast.walk(tree):
        t = _call_target(n, al)
        if not t or t[0] not in LOAD_MODULES or t[1] not in LOAD_NAMES:
            continue
        if file_strong or _weak_check_near(tree, n.lineno):
            continue
        kw = {k.arg: k.value for k in n.keywords if k.arg}
        wo = kw.get("weights_only")
        torch_safe = t[0] == "torch" and isinstance(wo, ast.Constant) and wo.value is True
        sev = "LOW" if torch_safe else ("HIGH" if t[0] in CODE_EXEC_MODULES else "MEDIUM")
        out.append(("NC-B1", sev, n.lineno, "%s.%s without manifest, schema or checksum check%s" % (
            t[0], t[1], " (weights_only=True reduces code-execution risk, integrity still unchecked)" if torch_safe else "")))
    return out


MODEL_TOKENS = ("model", "clf", "classifier", "regressor", "estimator", "pipeline", "network", "state_dict",
                "weights", "checkpoint", "ckpt", "booster", "forest", "svm", "net", "encoder", "scaler",
                "xgb", "lgbm", "gbm", "trained", "fitted", "predictor")
MODEL_EXTS = (".pt", ".pth", ".ckpt", ".onnx", ".h5", ".safetensors", ".joblib")


def _model_like(call):
    """Does the saved object / target path look like an ML model (vs. a dataset cache)?"""
    ids = set()
    for a in call.args[:2]:
        for x in ast.walk(a):
            if isinstance(x, ast.Name):
                ids.add(x.id.lower())
            elif isinstance(x, ast.Attribute):
                ids.add(x.attr.lower())
            elif isinstance(x, ast.Constant) and isinstance(x.value, str):
                ids.add(x.value.lower())
    return any(t in i for i in ids for t in MODEL_TOKENS) or any(i.endswith(MODEL_EXTS) for i in ids)


def check_saves(tree, lines):
    al, out = _aliases(tree), []
    file_strong = _has_strong(ast.walk(tree))
    for scope, _ in _scopes(tree):
        nodes = list(_scope_walk(scope))
        scope_strong = _has_strong(nodes)
        for n in nodes:
            t = _call_target(n, al)
            if t in SAVE_FUNCS and not scope_strong:
                if not _model_like(n):
                    sev, note = "LOW", "object does not look like a model (dataset/cache?); no checksum written"
                elif file_strong:
                    sev, note = "LOW", "checksum code exists elsewhere in the file, not in this function"
                else:
                    sev, note = "MEDIUM", "no checksum written"
                out.append(("NC-B6", sev, n.lineno, "%s.%s saves an artifact; %s (add a SHA-256 manifest next to it)" % (t[0], t[1], note)))
    return out


# ---------------------------------------------------------------- NC-B3
SCALERS = {"StandardScaler", "MinMaxScaler", "RobustScaler", "MaxAbsScaler", "Normalizer", "PowerTransformer",
           "QuantileTransformer", "SimpleImputer", "KNNImputer", "IterativeImputer", "PCA", "TruncatedSVD",
           "OneHotEncoder", "OrdinalEncoder", "LabelEncoder", "TargetEncoder", "TfidfVectorizer",
           "CountVectorizer", "SelectKBest", "VarianceThreshold", "KBinsDiscretizer"}
RESAMPLERS = {"SMOTE", "BorderlineSMOTE", "SVMSMOTE", "ADASYN", "RandomOverSampler", "RandomUnderSampler",
              "SMOTETomek", "SMOTEENN", "NearMiss", "TomekLinks"}
EVAL_WORDS = ("eval", "metric", "analy", "report", "plot", "backtest", "performance", "benchmark", "visual")
TARGET_COLS = {"label", "target", "y", "sepsis", "fraud", "default", "churn", "outcome", "readmitted",
               "clicked", "purchased", "converted"}
TARGET_VARS = {"y", "label", "target"}
FULL_NAMES = {"x", "df", "data", "dataset", "features", "full"}


def _is_full_data(a):
    base = a.value if isinstance(a, ast.Subscript) else a
    if not isinstance(base, ast.Name):
        return False
    n = base.id.lower()
    return not any(k in n for k in ("train", "test", "valid", "val")) and n in FULL_NAMES


def _assigned_from(tree, classes):
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and _call_name(n.value) in classes:
            names.update(k for k in (_recv_key(t) for t in n.targets) if k)
    return names


def check_leakage(tree, lines, path):
    scalers, resamplers = _assigned_from(tree, SCALERS), _assigned_from(tree, RESAMPLERS)
    out = []
    for scope, name in _scopes(tree):
        nodes = list(_scope_walk(scope))
        calls = [n for n in nodes if isinstance(n, ast.Call)]
        splits = [c.lineno for c in calls if _call_name(c) == "train_test_split"]
        text = (name + " " + os.path.basename(path or "")).lower()
        eval_scope = any(w in text for w in EVAL_WORDS)

        def scaler_fit(c):
            if _call_name(c) not in ("fit", "fit_transform") or not isinstance(c.func, ast.Attribute):
                return False
            r = c.func.value
            return (isinstance(r, ast.Call) and _call_name(r) in SCALERS) or _recv_key(r) in scalers

        fits = [c for c in calls if scaler_fit(c)]
        if splits:
            first = min(splits)
            for c in fits:
                if c.args and _is_full_data(c.args[0]):
                    if c.lineno < first:
                        out.append(("NC-B3", "HIGH", c.lineno, "scaler/transformer fit on full data before train_test_split (line %d)" % first))
                    else:
                        out.append(("NC-B3", "MEDIUM", c.lineno, "scaler/transformer fit on the unsplit variable although a split exists (line %d)" % first))
            for c in calls:
                if _call_name(c) == "fit_resample" and c.lineno < first and isinstance(c.func, ast.Attribute):
                    r = c.func.value
                    if ((isinstance(r, ast.Call) and _call_name(r) in RESAMPLERS) or _recv_key(r) in resamplers) \
                            and c.args and _is_full_data(c.args[0]):
                        out.append(("NC-B3", "HIGH", c.lineno, "resampling (SMOTE etc.) on full data before train_test_split (line %d)" % first))
        if fits and not eval_scope:
            for c in calls:
                if _call_name(c) == "concat":
                    ids = [x.id.lower() for a in c.args for x in ast.walk(a) if isinstance(x, ast.Name)]
                    if any("train" in i for i in ids) and any("test" in i for i in ids):
                        out.append(("NC-B3", "MEDIUM", c.lineno, "train and test concatenated in a scope that also fits a scaler"))
        if not eval_scope:
            for n in nodes:
                if not isinstance(n, ast.Assign):
                    continue
                keys = [k for k in (_subscript_key(t) for t in n.targets) if k]
                if not keys:
                    continue
                vals = list(ast.walk(n.value))
                gb = any(isinstance(v, ast.Call) and _call_name(v) == "groupby" for v in vals)
                tcol = any(isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value.lower() in TARGET_COLS for v in vals)
                if gb and tcol:
                    out.append(("NC-B3", "MEDIUM", n.lineno, "feature built from a groupby involving the target column (target encoding)"))
                elif any(w in k for k in keys for w in ("leak", "avg", "mean")) and any(
                        isinstance(v, ast.Name) and v.id.lower() in TARGET_VARS for v in vals):
                    out.append(("NC-B3", "HIGH", n.lineno, "feature column derived from the target variable"))
    return out


# ---------------------------------------------------------------- NC-B4
SQL_RE = re.compile(r"\b(select\s.+?\sfrom|insert\s+into|update\s.+?\sset|delete\s+from)\b", re.I | re.S)
SQL_SINKS = {"execute", "executemany", "executescript", "read_sql", "read_sql_query", "exec_driver_sql", "text", "raw"}
SQL_KWARGS = {"sql", "query", "statement", "stmt", "operation"}


def _sql_expr(n):
    """(text with ' ? ' for unknown parts, built dynamically?)"""
    if isinstance(n, ast.Constant):
        return (n.value if isinstance(n.value, str) else ""), False
    if isinstance(n, ast.JoinedStr):
        return ("".join(p.value if isinstance(p, ast.Constant) else " ? " for p in n.values),
                any(isinstance(p, ast.FormattedValue) for p in n.values))
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        (l, ld), (r, rd) = _sql_expr(n.left), _sql_expr(n.right)
        return l + r, ld or rd
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
        return _sql_expr(n.left)[0], True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and (n.args or n.keywords):
        return _sql_expr(n.func.value)[0], True
    return " ? ", True


def _dyn_sql(n):
    text, dyn = _sql_expr(n)
    return dyn and bool(SQL_RE.search(text))


def check_sql(tree, lines):
    out = []
    for scope, _ in _scopes(tree):
        nodes = sorted((n for n in _scope_walk(scope) if hasattr(n, "lineno")), key=lambda n: n.lineno)
        assigns, sqlish = {}, set()
        for n in nodes:
            if isinstance(n, ast.Assign):
                text = _sql_expr(n.value)[0]
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigns.setdefault(t.id, []).append((n.lineno, _dyn_sql(n.value)))
                        if SQL_RE.search(text):
                            sqlish.add(t.id)
            elif isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) and isinstance(n.target, ast.Name):
                if n.target.id in sqlish and _sql_expr(n.value)[1]:
                    assigns.setdefault(n.target.id, []).append((n.lineno, True))
        for n in nodes:
            if not isinstance(n, ast.Call) or _call_name(n) not in SQL_SINKS:
                continue
            args = list(n.args[:1]) + [k.value for k in n.keywords if k.arg in SQL_KWARGS]
            for a in args:
                earlier = sorted(x for x in assigns.get(getattr(a, "id", None), []) if x[0] < n.lineno)
                if _dyn_sql(a):
                    out.append(("NC-B4", "HIGH", n.lineno, "SQL string built with f-string/.format()/%/+ and executed; use bound parameters"))
                elif earlier and earlier[-1][1]:
                    out.append(("NC-B4", "MEDIUM", n.lineno, "variable holding dynamically built SQL (assigned line %d) is executed; use bound parameters" % earlier[-1][0]))
    return out


# ---------------------------------------------------------------- NC-B5
SECRET_NAME = re.compile(r"(password|passwd|pwd|secret|api_?key|access_?key|private_?key|aws_?key|aws_?secret|"
                         r"(?:auth|access|api|bearer|refresh|session|client)_?token|credential)", re.I)
NAME_EXCLUDE = re.compile(r"(_env|_var|_name|_path|_file|_field|_length|_len|_url|_header|_label|_type|_min|_max|_policy|_hint|_pattern)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$.*|\{.*\}|%.*|x+|\*+|your[_ -].*|change_?me.*|none|null|todo|example|password|secret|token|test|dummy)$", re.I)
ENV_LIKE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")
URL_PW = re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s@]+)@", re.I)
KNOWN = [("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
         ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
         ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
         ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
         ("API secret key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"))]


def _secret_value(v):
    if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
        return False
    s = v.value.strip()
    return len(s) >= 4 and not PLACEHOLDER.match(s) and not ENV_LIKE.match(s)


def _name_value_pairs(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                yield (_recv_key(t) or _subscript_key(t)), n.value
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            yield (_recv_key(n.target) or _subscript_key(n.target)), n.value
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


def check_credentials(tree, lines):
    found = {}
    for name, v in _name_value_pairs(tree):
        if name and SECRET_NAME.search(name) and not NAME_EXCLUDE.search(name) and _secret_value(v):
            sev = "HIGH" if len(v.value.strip()) >= 8 else "MEDIUM"
            found.setdefault(v.lineno, (sev, "secret literal assigned to `%s`; load it from environment or a secret store" % name))
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            for label, rx in KNOWN:
                if rx.search(n.value):
                    found.setdefault(n.lineno, ("HIGH", "hardcoded %s" % label))
            m = URL_PW.search(n.value)
            if m and not PLACEHOLDER.match(m.group(1)):
                found.setdefault(n.lineno, ("HIGH", "connection string with an embedded password"))
    return [("NC-B5", sev, ln, msg) for ln, (sev, msg) in sorted(found.items())]


# ---------------------------------------------------------------- driver
def audit_source(source, path="<string>"):
    """Audit Python source text. Returns the per-file result dict."""
    res = {"file": path, "result": "PASS", "highest_severity": None, "findings": []}
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as e:
        res.update(result="ERROR", error="could not parse: %s" % type(e).__name__)
        return res
    lines = source.split("\n")
    low = path.replace("\\", "/").lower()
    is_test = "test" in os.path.basename(low) or "/tests/" in low or "/test/" in low
    raw = check_loads(tree, lines) + check_leakage(tree, lines, path)
    if not is_test:   # tests commonly contain dummy secrets, raw SQL and throwaway saves
        raw += check_sql(tree, lines) + check_credentials(tree, lines) + check_saves(tree, lines)
    seen, findings = set(), []
    for rule, sev, line, msg in sorted(raw, key=lambda f: (f[2], f[0])):
        if (rule, line, msg) not in seen:
            seen.add((rule, line, msg))
            findings.append({"rule": rule, "severity": sev, "line": line, "code": _snip(lines, line), "message": msg})
    res["findings"] = findings
    if findings:
        top = max(findings, key=lambda f: SEV_RANK[f["severity"]])["severity"]
        res["highest_severity"] = top
        res["result"] = "FAIL" if SEV_RANK[top] >= 2 else "REVIEW"
    return res


def audit_file(path):
    """Scan ONE Python file; returns the per-file result dict."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return {"file": path, "result": "ERROR", "highest_severity": None, "findings": [],
                "error": "could not read: %s" % type(e).__name__}
    return audit_source(source, path)


run_audit_file = audit_file   # compatibility alias


def collect(paths):
    """Expand files/directories into a sorted list of .py files (explicit non-.py files are skipped)."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                files += [os.path.join(root, x) for x in sorted(names) if x.endswith(".py")]
        elif p.endswith(".py"):
            files.append(p)
    return files


def run_audit_v11(path, flagged_only=False):
    """Scan a file, a directory (recursively) or a list of them. Returns the full report dict."""
    paths = [path] if isinstance(path, str) else list(path)
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(p)
    results = [audit_file(f) for f in collect(paths)]
    summary = {"files": len(results)}
    summary.update({k: sum(r["result"] == k for r in results) for k in ("PASS", "REVIEW", "FAIL", "ERROR")})
    summary["findings_by_severity"] = {s: sum(f["severity"] == s for r in results for f in r["findings"]) for s in SEV_RANK}
    shown = [r for r in results if r["result"] != "PASS"] if flagged_only else results
    return {"tool": TOOL, "summary": summary, "files": shown}


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit_tier1_tool_v11.py",
        description="Static screening of Python code for NC-B1, NC-B3, NC-B4, NC-B5 and NC-B6 patterns. "
                    "Reads files only; never downloads or executes anything.")
    ap.add_argument("paths", nargs="+", help="Python files or directories (scanned recursively)")
    ap.add_argument("--flagged", action="store_true", help="list only files whose result is not PASS")
    ap.add_argument("-o", "--output", metavar="FILE", help="write the JSON report to FILE (summary still printed)")
    ap.add_argument("--fail-on", type=str.upper, choices=["HIGH", "MEDIUM", "LOW", "NONE"], default="HIGH",
                    help="exit with code 1 if any finding is at or above this severity (default: HIGH)")
    # parse_known_args: notebook kernels append arguments such as "-f kernel.json"; they are ignored
    args, _ = ap.parse_known_args(argv)
    paths = []
    for p in args.paths:
        if not os.path.exists(p):
            print("error: path not found: %s" % p, file=sys.stderr)
            return 2
        if os.path.isfile(p) and not p.endswith(".py"):
            print("note: skipping non-.py file: %s" % p, file=sys.stderr)
            continue
        paths.append(p)
    report = run_audit_v11(paths, flagged_only=args.flagged) if paths else None
    if report is None or report["summary"]["files"] == 0:
        print("error: no .py files found to scan", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(json.dumps(report["summary"], indent=2))
        print("report written to %s" % args.output)
    else:
        print(text)
    if args.fail_on == "NONE":
        return 0
    limit = SEV_RANK[args.fail_on]
    hit = any(SEV_RANK[f["severity"]] >= limit for r in report["files"] for f in r["findings"])
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())

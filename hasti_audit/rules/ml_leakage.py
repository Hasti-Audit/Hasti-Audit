from __future__ import annotations
import ast
import os
import re
from .base import make_finding
from ..context import key_of

SCALER_CLASSES = {"StandardScaler", "MinMaxScaler", "RobustScaler", "MaxAbsScaler", "Normalizer", "PowerTransformer",
                  "QuantileTransformer", "SimpleImputer", "KNNImputer", "IterativeImputer", "PCA", "TruncatedSVD",
                  "OneHotEncoder", "OrdinalEncoder", "LabelEncoder", "TfidfVectorizer", "CountVectorizer"}
SCALER_NAME_HINT = re.compile(r"(scaler|transformer|encoder|imputer|vectorizer|pca|normalizer)", re.I)
FULL_DATA_NAMES = {"x", "df", "data", "dataset", "features", "full"}
TARGET_COLS = {"label", "target", "y", "default", "is_default", "defaulted", "churn", "fraud", "outcome",
               "sepsis", "readmitted", "clicked", "purchased", "converted"}
EVAL_WORDS = ("eval", "metric", "analy", "report", "plot", "backtest", "performance", "benchmark", "visual")

class MlLeakageRule:
    rule_id = "NC-B3"

    def apply(self, context, tree, filename):
        findings = []
        scaler_names = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                c = n.value.func
                cname = c.attr if isinstance(c, ast.Attribute) else getattr(c, "id", None)
                if cname in SCALER_CLASSES:
                    scaler_names.update(k for k in (key_of(t) for t in n.targets) if k)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"fit", "fit_transform"}:
                r = node.func.value
                rname = r.func.attr if isinstance(r, ast.Call) and isinstance(r.func, ast.Attribute) else getattr(r.func, "id", None) if isinstance(r, ast.Call) else key_of(r)
                scaler_like = rname in SCALER_CLASSES or rname in scaler_names or bool(rname and SCALER_NAME_HINT.search(rname))
                if scaler_like and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.lower() in FULL_DATA_NAMES:
                    findings.append(make_finding("NC-B3", "MEDIUM", "scaler/transformer fit on the full dataset; fit on the training split only", filename, node.lineno))
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
                        findings.append(make_finding("NC-B3", "MEDIUM", "target encoding via groupby/transform on a target column (leakage unless computed inside CV folds)", filename, node.lineno))
        return findings

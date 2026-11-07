from __future__ import annotations
import ast
import os
import re
from .base import make_finding
from ..context import key_of

TARGET_ENCODING_MODE = "warn"

SCALER_CLASSES = {
    "StandardScaler", "MinMaxScaler", "RobustScaler", "MaxAbsScaler",
    "Normalizer", "PowerTransformer", "QuantileTransformer",
    "SimpleImputer", "KNNImputer", "IterativeImputer",
    "PCA", "TruncatedSVD", "OneHotEncoder", "OrdinalEncoder",
    "LabelEncoder", "TfidfVectorizer", "CountVectorizer",
}

SCALER_NAME_HINT = re.compile(r"(scaler|transformer|encoder|imputer|vectorizer|pca|normalizer)", re.I)
FULL_DATA_NAMES = {"x", "df", "data", "dataset", "features", "full"}
TARGET_COLS = {
    "label", "target", "y", "default", "is_default", "defaulted",
    "churn", "fraud", "outcome", "sepsis", "readmitted", "clicked",
    "purchased", "converted",
}
EVAL_WORDS = ("eval", "metric", "analy", "report", "plot", "backtest",
              "performance", "benchmark", "visual")


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

        for scope in context.iter_scopes():
            if scope is context.tree:
                continue
            scope_nodes = [n for n in ast.walk(scope) if hasattr(n, "lineno")]
            split_lines = [
                n.lineno for n in scope_nodes
                if isinstance(n, ast.Call) and (
                    isinstance(n.func, ast.Name) and n.func.id == "train_test_split"
                    or isinstance(n.func, ast.Attribute) and n.func.attr == "train_test_split"
                )
            ]
            has_split = len(split_lines) > 0
            first_split_line = min(split_lines) if split_lines else None

            for node in scope_nodes:
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"fit", "fit_transform"}:
                    r = node.func.value
                    if isinstance(r, ast.Call):
                        if isinstance(r.func, ast.Attribute):
                            rname = r.func.attr
                        else:
                            rname = getattr(r.func, "id", None)
                    else:
                        rname = key_of(r)

                    scaler_like = (
                        rname in SCALER_CLASSES
                        or rname in scaler_names
                        or bool(rname and SCALER_NAME_HINT.search(rname))
                    )
                    if scaler_like and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.lower() in FULL_DATA_NAMES:
                        if has_split:
                            msg = f"scaler/transformer fit on the full dataset before train_test_split (line {first_split_line}); fit on the training split only"
                            findings.append(make_finding("NC-B3", "MEDIUM", msg, filename, node.lineno))

        if not any(w in os.path.basename(filename).lower() for w in EVAL_WORDS):
            for scope in context.iter_scopes():
                if scope is context.tree:
                    continue
                scope_nodes = [n for n in ast.walk(scope) if hasattr(n, "lineno")]
                has_split = any(
                    isinstance(n, ast.Call) and (
                        isinstance(n.func, ast.Name) and n.func.id == "train_test_split"
                        or isinstance(n.func, ast.Attribute) and n.func.attr == "train_test_split"
                    )
                    for n in scope_nodes
                )
                if not has_split:
                    for node in scope_nodes:
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "transform":
                            chain = list(ast.walk(node.func.value))
                            if any(
                                isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "groupby"
                                for c in chain
                            ) and any(
                                isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.lower() in TARGET_COLS
                                for c in chain
                            ):
                                findings.append(make_finding(
                                    "NC-B3", "MEDIUM",
                                    "target encoding via groupby/transform on a target column (leakage unless computed inside CV folds)",
                                    filename, node.lineno,
                                ))
        return findings

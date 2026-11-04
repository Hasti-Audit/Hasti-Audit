from __future__ import annotations
import ast
import re
from .base import make_finding
from ..context import fold_str, name_value_pairs

SECRET_NAME = re.compile(r"(password|passwd|pwd|secret|api_?key|access_?key|private_?key|aws_?key|(?:auth|access|api|bearer|refresh|session|client)_?token|credential)", re.I)
NAME_EXCLUDE = re.compile(r"(_env|_var|_name|_path|_file|_field|_length|_len|_url|_header|_label|_type|_min|_max|_policy|_hint|_pattern)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$.*|\{.*\}|%.*|x+|\*+|your[_ -].*|change_?me.*|none|null|todo|example|password|secret|token|test|dummy)$", re.I)
ENV_LIKE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")
URL_PW = re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s@]+)@", re.I)
SECRET_PATTERNS = [("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
                   ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}")),
                   ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
                   ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
                   ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"))]

class HardcodedSecretsRule:
    rule_id = "NC-SECRET"

    def apply(self, context, tree, filename):
        secret_lines = {}
        for name, value in name_value_pairs(tree):
            if name and SECRET_NAME.search(name) and not NAME_EXCLUDE.search(name):
                text = fold_str(value)
                if text is not None and len(text.strip()) >= 4 and not PLACEHOLDER.match(text.strip()) and not ENV_LIKE.match(text.strip()):
                    secret_lines.setdefault(value.lineno, f"Hardcoded secret assigned to '{name}'")
        for n in ast.walk(tree):
            text = fold_str(n) if isinstance(n, (ast.Constant, ast.BinOp)) else None
            if not text: continue
            for label, rx in SECRET_PATTERNS:
                if rx.search(text):
                    secret_lines.setdefault(n.lineno, f"Hardcoded {label}")
            m = URL_PW.search(text)
            if m and not PLACEHOLDER.match(m.group(1)):
                secret_lines.setdefault(n.lineno, "Connection string with an embedded password")
        return [make_finding("NC-SECRET", "HIGH", msg, filename, ln) for ln, msg in secret_lines.items()]

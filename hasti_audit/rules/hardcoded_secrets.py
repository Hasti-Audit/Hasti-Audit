from __future__ import annotations
import ast
import re

from .base import make_finding
from ..context import fold_str, name_value_pairs


SECRET_NAME = re.compile(
    r"(password|passwd|pwd|secret|api_?key|access_?key|private_?key|aws_?key|"
    r"(?:auth|access|api|bearer|refresh|session|client)_?token)",
    re.I,
)
# Removed "credential" from SECRET_NAME: it matches standard CORS headers
# like "Access-Control-Allow-Credentials", producing false positives.

NAME_EXCLUDE = re.compile(
    r"(_env|_var|_name|_path|_file|_field|_length|_len|_url|_header|_label|"
    r"_type|_min|_max|_policy|_hint|_pattern|_allow|_control)$",
    re.I,
)
# Added "_allow" and "_control" to exclude CORS header names.

PLACEHOLDER = re.compile(
    r"^(<.*>|\$.*|\{.*\}|%.*|x+|\*+|your[_ -].*|change_?me.*|none|null|todo|"
    r"example|password|secret|token|test|dummy|true|false)$",
    re.I,
)
# Added "true" / "false": CORS headers use literal "true" as a value.

ENV_LIKE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")
URL_PW = re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s@]+)@", re.I)

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


class HardcodedSecretsRule:
    rule_id = "NC-SECRET"

    def apply(self, context, tree, filename):
        secret_lines = {}

        # --- Pass 1: name-based detection ---
        for name, value in name_value_pairs(tree):
            if not name or not SECRET_NAME.search(name) or NAME_EXCLUDE.search(name):
                continue
            text = fold_str(value)
            if text is None:
                continue
            stripped = text.strip()
            if len(stripped) < 4:
                continue
            if PLACEHOLDER.match(stripped):
                continue
            if ENV_LIKE.match(stripped):
                continue
            # FIX 1: enum-like or constant-like assignments are not secrets.
            # If the value equals the variable name (case-insensitive),
            # it's a symbolic constant (e.g., apiKey = "apiKey").
            if stripped.lower() == name.lower():
                continue
            secret_lines.setdefault(value.lineno, f"Hardcoded secret assigned to '{name}'")

        # --- Pass 2: pattern-based detection (AKIA..., sk_live_..., etc.) ---
        for n in ast.walk(tree):
            text = fold_str(n) if isinstance(n, (ast.Constant, ast.BinOp)) else None
            if not text:
                continue
            for label, rx in SECRET_PATTERNS:
                if rx.search(text):
                    secret_lines.setdefault(n.lineno, f"Hardcoded {label}")
            m = URL_PW.search(text)
            if m and not PLACEHOLDER.match(m.group(1)):
                secret_lines.setdefault(n.lineno, "Connection string with an embedded password")

        return [
            make_finding("NC-SECRET", "HIGH", msg, filename, ln)
            for ln, msg in secret_lines.items()
        ]

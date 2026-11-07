from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import List

from hasti_audit.engine import audit_source
from hasti_audit.reporters.console import render_console
from hasti_audit.reporters.json_reporter import render_json


SKIP_DIRS = {
    ".git", "__pycache__", "venv", ".venv", "node_modules", "env", ".tox",
    "docs", "docs_src", "tests", "test", "examples", "benchmarks",
}


def _iter_py_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    files: List[Path] = []
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        files.append(p)
    return sorted(files)


def cmd_scan(args):
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 2
    files = _iter_py_files(root)
    all_findings = []
    parse_or_read_errors = 0
    for fp in files:
        try:
            code = fp.read_text(encoding="utf-8", errors="ignore")
            rel = str(fp) if args.absolute else str(fp.relative_to(root if root.is_dir() else root.parent))
            findings = audit_source(code, filename=rel)
            all_findings.extend(findings)
        except Exception as e:
            parse_or_read_errors += 1
            if args.verbose:
                print(f"skip {fp}: {e}", file=sys.stderr)
    high = sum(1 for f in all_findings if str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"})
    if args.json or (args.out and str(args.out).endswith(".json")):
        text = render_json(all_findings, path=str(root))
    else:
        text = render_console(all_findings, title=f"Hasti Audit — {root.name}")
        text += f"\nFiles scanned: {len(files)} | Read errors: {parse_or_read_errors}\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(text)
    if args.fail_on_findings and all_findings:
        return 1
    if args.fail_on_high and high:
        return 1
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="hasti_audit", description="Hasti AST static pre-check")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Scan a file or directory")
    s.add_argument("path", nargs="?", default=".", help="File or directory (default: .)")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.add_argument("--out", default="", help="Write report to file")
    s.add_argument("--absolute", action="store_true", help="Use absolute file paths")
    s.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if any finding")
    s.add_argument("--fail-on-high", action="store_true", help="Exit 1 if any HIGH/CRITICAL")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

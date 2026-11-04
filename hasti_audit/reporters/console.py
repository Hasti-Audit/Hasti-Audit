from __future__ import annotations
from typing import Any, Dict, List

def render_console(findings: List[Dict[str, Any]], title: str = "Hasti Audit") -> str:
    lines = [f"=== {title} ===", f"Findings: {len(findings)}", ""]
    if not findings:
        lines.append("No issues matched the current rule set.")
        return "\n".join(lines)
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f.get('severity', '?')}] {f.get('id', '?')} | "
            f"{f.get('file', '?')}:{f.get('line', '?')} | {f.get('message', '')}"
        )
    lines.append("")
    lines.append("Technical indicators only — not a certification.")
    return "\n".join(lines)

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

def render_json(findings: List[Dict[str, Any]], *, tool: str = "hasti_audit", path: str = "") -> str:
    payload = {
        "tool": tool,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "path": path,
        "finding_count": len(findings),
        "findings": findings,
        "disclaimer": "Technical indicators only. Not a certification or legal advice.",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    confidence: float = 0.8
    recommendation: str = ""

    def __post_init__(self) -> None:
        sev = (self.severity or "MEDIUM").upper()
        if sev not in SEVERITIES:
            sev = "MEDIUM"
        self.severity = sev
        try:
            c = float(self.confidence)
        except (TypeError, ValueError):
            c = 0.5
        self.confidence = max(0.0, min(1.0, c))
        if self.line is not None:
            try:
                self.line = int(self.line)
            except (TypeError, ValueError):
                self.line = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_legacy_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "message": self.message,
            "file": self.file,
        }

def findings_to_legacy(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [f.to_legacy_dict() for f in findings]

DEFAULT_CONFIDENCE = {
    "NC-B1": 0.9, "NC-TORCH": 0.9, "NC-YAML": 0.9, "NC-SHELL": 0.85,
    "NC-DYN": 0.9, "NC-SQL": 0.8, "NC-SECRET": 0.75, "NC-B3": 0.55, "NC-PARSE": 1.0,
}

from __future__ import annotations

def make_finding(rule_id, severity, message, filename, line=None, confidence=0.8, recommendation=""):
    from ..models import Finding, DEFAULT_CONFIDENCE
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=filename,
        line=line,
        confidence=DEFAULT_CONFIDENCE.get(rule_id, confidence),
        recommendation=recommendation,
    )

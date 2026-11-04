from __future__ import annotations
from typing import Dict, List, Protocol, TYPE_CHECKING
if TYPE_CHECKING:
    import ast
    from .models import Finding
    from .context import AnalysisContext

class Rule(Protocol):
    rule_id: str
    def apply(self, context: "AnalysisContext", tree: "ast.AST", filename: str) -> List["Finding"]: ...

class RuleRegistry:
    def __init__(self) -> None:
        self._rules: Dict[str, Rule] = {}
    def register(self, rule: Rule) -> None:
        self._rules[rule.rule_id] = rule
    def all_rules(self) -> List[Rule]:
        return list(self._rules.values())

registry = RuleRegistry()

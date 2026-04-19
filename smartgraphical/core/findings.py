from dataclasses import dataclass, field


@dataclass
class FindingEvidence:
    kind: str
    summary: str
    type_name: str = ""
    function_name: str = ""
    statement: str = ""


@dataclass
class Finding:
    task_id: str
    legacy_code: int
    rule_id: str
    title: str
    category: str
    portability: str
    confidence: str
    message: str
    remediation_hint: str
    evidences: list = field(default_factory=list)

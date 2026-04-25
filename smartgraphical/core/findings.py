from dataclasses import dataclass, field


@dataclass
class FindingEvidence:
    kind: str
    summary: str
    type_name: str = ""
    function_name: str = ""
    statement: str = ""
    source_statement: str = ""
    confidence_reason: str = ""
    line_number: int = 0
    line_numbers: list = field(default_factory=list)


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

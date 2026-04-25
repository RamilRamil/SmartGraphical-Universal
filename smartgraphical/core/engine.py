import re
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, List

from smartgraphical.core.findings import Finding, FindingEvidence

_SOURCE_LINES_CACHE = {}


def _source_lines_for_model(model):
    artifact = getattr(model, "artifact", None)
    if artifact is None:
        return []
    source_path = getattr(artifact, "path", "") or ""
    if not source_path:
        return []
    if source_path in _SOURCE_LINES_CACHE:
        return _SOURCE_LINES_CACHE[source_path]
    path_obj = Path(source_path)
    if not path_obj.exists():
        _SOURCE_LINES_CACHE[source_path] = []
        return []
    try:
        lines = path_obj.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        lines = []
    _SOURCE_LINES_CACHE[source_path] = lines
    return lines


def _infer_line_numbers(model, statement):
    text = (statement or "").strip()
    if not text:
        return []
    matches = []
    for index, line in enumerate(_source_lines_for_model(model), start=1):
        if text in line:
            matches.append(index)
    return matches


@dataclass
class RuleSpec:
    task_id: str
    legacy_code: int
    slug: str
    title: str
    category: str
    portability: str
    confidence: str
    remediation_hint: str
    runner: Callable  # (AnalysisContext) -> list[Finding]


def _infer_evidence(message, model):
    evidence = FindingEvidence(
        kind='message',
        summary=message,
        confidence_reason='message_only_fallback',
    )
    quoted_parts = re.findall(r"'([^']+)'", message)
    if 'line:' in message:
        evidence.statement = message.split('line:', 1)[1].strip()
    elif quoted_parts:
        evidence.statement = quoted_parts[-1]
    evidence.source_statement = evidence.statement
    evidence.line_numbers = _infer_line_numbers(model, evidence.source_statement)
    evidence.line_number = evidence.line_numbers[0] if evidence.line_numbers else 0
    findings_data = getattr(model, 'findings_data', None)
    if findings_data:
        for function_key, evidences in findings_data.evidence_index.items():
            for mapped_evidence in evidences:
                mapped_statement = mapped_evidence.get('source_statement', '')
                if mapped_statement and mapped_statement in message:
                    evidence.type_name = mapped_evidence.get('type_name', '')
                    evidence.function_name = mapped_evidence.get('function_name', '')
                    evidence.source_statement = mapped_statement
                    evidence.statement = mapped_statement
                    evidence.line_numbers = _infer_line_numbers(model, mapped_statement)
                    evidence.line_number = evidence.line_numbers[0] if evidence.line_numbers else 0
                    evidence.confidence_reason = mapped_evidence.get(
                        'confidence_reason',
                        'matched_statement_from_normalized_model',
                    )
                    return evidence
            if function_key in message:
                type_name, function_name = function_key.split('.', 1)
                evidence.type_name = type_name
                evidence.function_name = function_name
                evidence.confidence_reason = 'matched_qualified_function_name'
                return evidence
    for type_entry in model.types:
        if type_entry.name in message:
            evidence.type_name = type_entry.name
            evidence.confidence_reason = 'matched_type_name'
        for function in type_entry.functions:
            if function.name in message:
                evidence.type_name = type_entry.name
                evidence.function_name = function.name
                evidence.confidence_reason = 'matched_function_name'
                return evidence
    return evidence


def make_findings(alerts, model, task_id, legacy_code, slug, title,
                  category, portability, confidence, remediation_hint):
    """Convert raw alert dicts into Finding objects.

    This is the shared helper used by all rule run() functions.
    """
    findings = []
    for alert in alerts:
        message = alert.get('message', '')
        findings.append(Finding(
            task_id=task_id,
            legacy_code=alert.get('code', legacy_code),
            rule_id=slug,
            title=title,
            category=category,
            portability=portability,
            confidence=confidence,
            message=message,
            remediation_hint=remediation_hint,
            evidences=[_infer_evidence(message, model)],
        ))
    return findings


def merge_alerts(*alert_groups):
    """Merge alert groups with stable ordering and deduplication."""
    merged = []
    seen = set()
    for group in alert_groups:
        for alert in group:
            code = alert.get('code')
            message = str(alert.get('message', '')).replace('\n', ' ').strip()
            key = (code, message)
            if key in seen:
                continue
            seen.add(key)
            merged.append({'code': code, 'message': message})
    return merged


# ---------------------------------------------------------------------------
# Kept for backward compatibility (SmartGraphical.py legacy path)
# ---------------------------------------------------------------------------

def infer_evidence_from_message(message, model):
    return _infer_evidence(message, model)


def convert_alerts_to_findings(rule_spec, alerts, context):
    return make_findings(
        alerts, context.normalized_model,
        rule_spec.task_id, rule_spec.legacy_code, rule_spec.slug,
        rule_spec.title, rule_spec.category, rule_spec.portability,
        rule_spec.confidence, rule_spec.remediation_hint,
    )


# ---------------------------------------------------------------------------
# Model summary
# ---------------------------------------------------------------------------

def summarize_model(context):
    model = context.normalized_model
    function_count = sum(len(t.functions) for t in model.types)
    state_count = sum(len(t.state_entities) for t in model.types)
    guard_count = sum(len(f.guards) for t in model.types for f in t.functions)
    print("--------------------------------------------------------------------------")
    print("Exploration summary")
    print(f"Artifact: {model.artifact.path}")
    print(f"Adapter: {model.artifact.adapter_name}")
    print(f"Types: {len(model.types)}")
    print(f"Functions: {function_count}")
    print(f"State entities: {state_count}")
    print(f"Guards: {guard_count}")
    print(f"Call edges: {len(model.call_edges)}")
    print("Portable rule core candidates: " + ", ".join(model.second_language_poc.portable_rule_tasks))
    print("Second-language PoC criteria:")
    for criterion in model.second_language_poc.success_criteria:
        print(f"- {criterion}")


# ---------------------------------------------------------------------------
# Finding display
# ---------------------------------------------------------------------------

def demonstrate_findings(findings, output_mode='auditor'):
    if output_mode == 'legacy':
        for finding in findings:
            print({'code': finding.legacy_code, 'message': finding.message})
            print("\n    ----------------------      \n")
        return

    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print(f"[Task {finding.task_id}] {finding.title}")
        print(f"Category: {finding.category}")
        print(f"Portability: {finding.portability}")
        print(f"Confidence: {finding.confidence}")
        print(f"Message: {finding.message}")
        if finding.remediation_hint:
            print(f"Hint: {finding.remediation_hint}")
        for evidence in finding.evidences:
            print(f"Evidence: {evidence.summary}")
            if evidence.type_name:
                print(f"Type: {evidence.type_name}")
            if evidence.function_name:
                print(f"Function: {evidence.function_name}")
            if evidence.statement:
                print(f"Statement: {evidence.statement}")
            if evidence.confidence_reason:
                print(f"Reason: {evidence.confidence_reason}")
        print("\n    ----------------------      \n")


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rule_registry):
        self.rule_registry = rule_registry

    def run_task(self, context, task_id):
        """Run a single rule. runner(context) -> list[Finding]."""
        rule_spec = self.rule_registry[task_id]
        return rule_spec.runner(context)

    def run_all(self, context):
        findings = []
        for task_id in sorted(self.rule_registry.keys(), key=int):
            findings.extend(self.run_task(context, task_id))
        return findings

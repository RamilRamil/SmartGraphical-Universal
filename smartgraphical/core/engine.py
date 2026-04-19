import re
from dataclasses import dataclass

from smartgraphical.core.findings import Finding, FindingEvidence


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
    runner: object


def infer_evidence_from_message(message, model):
    evidence = FindingEvidence(kind="message", summary=message)
    quoted_parts = re.findall(r"'([^']+)'", message)
    if "line:" in message:
        evidence.statement = message.split("line:", 1)[1].strip()
    elif len(quoted_parts) > 0:
        evidence.statement = quoted_parts[-1]

    for type_entry in model.types:
        if type_entry.name in message:
            evidence.type_name = type_entry.name
        for function in type_entry.functions:
            if function.name in message:
                evidence.type_name = type_entry.name
                evidence.function_name = function.name
                return evidence
    return evidence


def convert_alerts_to_findings(rule_spec, alerts, context):
    findings = []
    for alert in alerts:
        message = alert.get("message", "")
        findings.append(
            Finding(
                task_id=rule_spec.task_id,
                legacy_code=alert.get("code", rule_spec.legacy_code),
                rule_id=rule_spec.slug,
                title=rule_spec.title,
                category=rule_spec.category,
                portability=rule_spec.portability,
                confidence=rule_spec.confidence,
                message=message,
                remediation_hint=rule_spec.remediation_hint,
                evidences=[infer_evidence_from_message(message, context.normalized_model)],
            )
        )
    return findings


def summarize_model(context):
    model = context.normalized_model
    function_count = 0
    state_count = 0
    guard_count = 0
    for type_entry in model.types:
        function_count += len(type_entry.functions)
        state_count += len(type_entry.state_entities)
        for function in type_entry.functions:
            guard_count += len(function.guards)
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


def demonstrate_findings(findings, output_mode="auditor"):
    if output_mode == "legacy":
        for finding in findings:
            print({"code": finding.legacy_code, "message": finding.message})
            print("\n    ----------------------      \n")
        return

    if len(findings) == 0:
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
        print("\n    ----------------------      \n")


class RuleEngine:
    def __init__(self, rule_registry):
        self.rule_registry = rule_registry

    def run_task(self, context, task_id):
        context.bind_legacy_runtime()
        rule_spec = self.rule_registry[task_id]
        alerts = rule_spec.runner()
        return convert_alerts_to_findings(rule_spec, alerts, context)

    def run_all(self, context):
        findings = []
        for task_id in sorted(self.rule_registry.keys(), key=int):
            findings.extend(self.run_task(context, task_id))
        return findings

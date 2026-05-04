"""Shared assertions for AnalysisService analyze + run_all integration tests."""

import json
import os
from collections import Counter


def narrow_normalized_model_shape_json(model):
    """Minimal stable digest for phase-5 snapshots (language, basename, typed names).

    Omit bodies and evidence; adapters for Solidity/C share normalized_model shape.
    """
    types_out = []
    for t in getattr(model, "types", []) or []:
        types_out.append(
            {
                "type_name": t.name,
                "functions": sorted({f.name for f in getattr(t, "functions", []) or []}),
                "state_entities": sorted(
                    {s.name for s in getattr(t, "state_entities", []) or []}
                ),
            }
        )
    types_out.sort(key=lambda entry: entry["type_name"])
    artifact = getattr(model, "artifact", None)
    payload = {
        "artifact_language": getattr(artifact, "language", ""),
        "basename": os.path.basename(getattr(artifact, "path", "") or ""),
        "types": types_out,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def assert_pipeline_findings(testcase, findings, expected_rule_ids):
    testcase.assertIsInstance(findings, list)
    seen_rule_ids = {f.rule_id for f in findings}
    unknown = seen_rule_ids - expected_rule_ids
    testcase.assertFalse(
        unknown,
        msg=(
            "Unexpected finding rule_id (expected allowlist stale or wrong engine): "
            f"{unknown}"
        ),
    )
    for finding in findings:
        testcase.assertTrue(finding.rule_id)
        testcase.assertTrue(finding.title)
        testcase.assertTrue(finding.task_id)
        testcase.assertTrue(finding.message)
    grouped = Counter((f.rule_id, f.message) for f in findings)
    duplicated = [key for key, count in grouped.items() if count > 1]
    testcase.assertEqual(duplicated, [], msg=f"Duplicate findings inside same rule: {duplicated}")
    for finding in findings:
        testcase.assertTrue(
            finding.evidences,
            msg=f"Finding {finding.rule_id} has no evidence",
        )

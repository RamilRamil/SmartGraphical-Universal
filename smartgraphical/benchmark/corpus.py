"""Labeled benchmark corpus: measure rule precision/recall against human-authored
ground truth (feature 014).

Pure measurement over `web_api.analyze_all` output. The match key is the location
projection of the shared finding identity: (rule_id, type_name, function_name) —
the same fields `history_service._finding_key` uses, at location granularity so
human labels are stable. Findings/labels that share a key collapse to one match
unit (documented edge case). See contracts/benchmark.md.
"""
import json
import os


class BenchmarkError(Exception):
    """Raised for malformed or stale labels / corpus configuration."""


def match_key(finding):
    """(rule_id, type_name, function_name) of an emitted finding dict."""
    evidences = finding.get("evidences") or []
    ev = evidences[0] if evidences else {}
    return (
        str(finding.get("rule_id", "") or ""),
        str(ev.get("type_name", "") or ""),
        str(ev.get("function_name", "") or ""),
    )


def _entry_key(entry):
    """Same key from a label entry."""
    return (
        str(entry.get("rule_id", "") or ""),
        str(entry.get("type_name", "") or ""),
        str(entry.get("function_name", "") or ""),
    )


def load_labels(path):
    """Parse one label file; raise BenchmarkError (naming the file) on problems."""
    if not os.path.isfile(path):
        raise BenchmarkError(f"label file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"label file {path} is not valid JSON: {exc}")
    if not isinstance(data, dict) or not data.get("example"):
        raise BenchmarkError(f"label file {path} must be an object with a non-empty 'example'")
    for bucket in ("expected", "false_positives"):
        entries = data.get(bucket, []) or []
        if not isinstance(entries, list):
            raise BenchmarkError(f"label file {path}: '{bucket}' must be a list")
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("rule_id"):
                raise BenchmarkError(
                    f"label file {path}: each '{bucket}' entry needs a 'rule_id'"
                )
    data.setdefault("expected", [])
    data.setdefault("false_positives", [])
    return data


def _rule_metrics(emitted, expected, fps):
    found = expected & emitted
    labeled_fp = fps & emitted
    return {
        "expected_total": len(expected),
        "found": sorted(found),
        "missed": sorted(expected - emitted),
        "labeled_fp": sorted(labeled_fp),
        "unexpected": sorted(emitted - expected - fps),
        "recall": (len(found) / len(expected)) if expected else None,
        "precision": (
            len(found) / (len(found) + len(labeled_fp))
            if (found or labeled_fp)
            else None
        ),
    }


def evaluate(findings, label_file):
    """Per-example metrics + a per-rule breakdown. Operates on match-key sets, so
    findings sharing a key collapse to one unit."""
    emitted = {match_key(f) for f in findings}
    expected = {_entry_key(e) for e in label_file.get("expected", [])}
    fps = {_entry_key(e) for e in label_file.get("false_positives", [])}

    result = _rule_metrics(emitted, expected, fps)
    result["example"] = label_file.get("example", "")

    by_rule = {}
    for rid in sorted({k[0] for k in (expected | fps | emitted)}):
        by_rule[rid] = _rule_metrics(
            {k for k in emitted if k[0] == rid},
            {k for k in expected if k[0] == rid},
            {k for k in fps if k[0] == rid},
        )
    result["by_rule"] = by_rule
    return result


def _aggregate_overall(per_example):
    total_expected = sum(r["expected_total"] for r in per_example)
    total_found = sum(len(r["found"]) for r in per_example)
    total_fp = sum(len(r["labeled_fp"]) for r in per_example)
    total_unexpected = sum(len(r["unexpected"]) for r in per_example)
    return {
        "expected_total": total_expected,
        "found": total_found,
        "missed": total_expected - total_found,
        "labeled_fp": total_fp,
        "unexpected": total_unexpected,
        "recall": (total_found / total_expected) if total_expected else None,
        "precision": (
            total_found / (total_found + total_fp)
            if (total_found or total_fp)
            else None
        ),
    }


def run_corpus(labels_dir, examples_dir, analyze, language="solidity"):
    """Analyze every labeled example via `analyze(path, language)` and aggregate.

    `analyze` is injected (web_api.analyze_all in production; a fake in tests) so
    this stays pure and deterministic.
    """
    examples = {}
    for name in sorted(os.listdir(labels_dir)):
        if not name.endswith(".json"):
            continue
        label = load_labels(os.path.join(labels_dir, name))
        example_path = os.path.join(examples_dir, label["example"])
        if not os.path.isfile(example_path):
            raise BenchmarkError(
                f"label {name}: example file not found: {example_path}"
            )
        report = analyze(example_path, language)
        findings = report.get("findings", []) if isinstance(report, dict) else []
        examples[label["example"]] = evaluate(findings, label)
    overall = _aggregate_overall(list(examples.values()))
    return {"examples": examples, "overall": overall}

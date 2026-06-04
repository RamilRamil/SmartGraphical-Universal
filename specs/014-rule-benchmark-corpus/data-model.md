# Phase 1 Data Model: Benchmark Corpus

Versioned files + pure value types. No database.

## Entity: Label entry

One declared finding in a label file, addressed by the benchmark match key.

| Field | Meaning |
|-------|---------|
| `rule_id` | the rule that should (or wrongly does) fire |
| `type_name` | owning contract/type |
| `function_name` | owning function (may be empty for type-level findings) |
| `note` | human rationale (why real / why a false positive) |
| `line` | optional, informational only (not used for matching) |

## Entity: Label file (per example)

`tests/benchmark/labels/<example>.json`:

| Field | Meaning |
|-------|---------|
| `example` | example filename under `examples/` |
| `expected` | list of Label entries that are **real** findings (ground truth) |
| `false_positives` | list of Label entries that are emitted but **not real** |

Validation:
- `example` MUST reference an existing file under `examples/`.
- each entry MUST have `rule_id` and `type_name`; `function_name` may be empty.
- malformed JSON or missing required fields → clear error naming the file (FR-010).

## Match key (shared identity projection)

`match_key(finding) = (finding.rule_id, evidence.type_name, evidence.function_name)`
where `evidence = finding.evidences[0]` (the same fields `_finding_key` derives;
the location-bearing prefix of the shared finding identity). Labels carry the same
three fields, so a label and an emitted finding match iff their `match_key` is equal.

## Entity: Per-rule / overall result

Computed by `evaluate(findings, label_file)`:

| Field | Meaning |
|-------|---------|
| `expected_total` | count of `expected` labels |
| `found` (TP) | expected labels whose key is emitted |
| `missed` (FN) | expected labels not emitted (listed) |
| `labeled_fp` | `false_positives` labels whose key is emitted |
| `unexpected` | emitted keys matching neither list (listed) |
| `recall` | `found / expected_total` (N/A when `expected_total == 0`) |
| `precision` | `found / (found + labeled_fp)` (N/A when denominator 0) |

Aggregated **per rule_id**, **per category**, and **overall** across the corpus.

## Entity: Baseline

`tests/benchmark/baseline.json` — `{ "<example>": { "recall": <float> } }`,
recorded from the first green run; the guard asserts current recall >= baseline.

## Determinism

All lists in the result/report are sorted by stable keys (rule_id, type, function)
so re-runs are byte-identical.

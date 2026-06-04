# Contract: Benchmark module, labels, and runner

## Pure module: `smartgraphical/benchmark/corpus.py`

```python
def match_key(finding: dict) -> tuple[str, str, str]:
    """(rule_id, type_name, function_name) from evidences[0]; the shared identity's
    location projection. Used to match emitted findings to labels."""

def load_labels(path: str) -> dict:
    """Parse one label file; raise a clear, file-named error on malformed/missing
    fields (FR-010). Returns {example, expected:[...], false_positives:[...]}."""

def evaluate(findings: list[dict], label_file: dict) -> dict:
    """Match findings to labels; return per-rule + overall metrics
    (expected_total, found, missed, labeled_fp, unexpected, recall, precision)."""

def run_corpus(labels_dir: str, examples_dir: str, analyze) -> dict:
    """For each label file: analyze the example (via the injected `analyze`
    callable = web_api.analyze_all), evaluate, aggregate. Deterministic."""
```

- **R1 (pure)**: `match_key` / `load_labels` / `evaluate` have no I/O beyond
  reading the given label path; `run_corpus` takes the analyzer as a parameter so
  it is testable with a fake.
- **R2 (one identity)**: `match_key` uses the same fields as `_finding_key`; no
  separate identity scheme.
- **R3 (deterministic)**: outputs sorted by `(rule_id, type, function)`.
- **R4 (no analyzer change)**: the module only reads findings; it never imports or
  mutates rules/adapters.

## Label file format (versioned data)

`tests/benchmark/labels/<example>.json` — see data-model.md. `expected` =
ground-truth real findings; `false_positives` = emitted-but-not-real. Each entry:
`{ rule_id, type_name, function_name, note, line? }`.

## Baseline

`tests/benchmark/baseline.json` — `{ "<example>": { "recall": <float> } }`.

## Runner CLI: `sg_benchmark.py`

```text
python sg_benchmark.py [--json] [--labels tests/benchmark/labels]
```
- Default: prints a human-readable per-rule/per-category/overall precision+recall
  table plus missed/unexpected lists.
- `--json`: prints the machine-readable aggregate (stable, parseable).
- Exit code 0 always for reporting (the CI gate is the guard test, not this CLI).

## Guard test: `tests/benchmark/test_benchmark.py`

- Unit: `evaluate` on synthetic findings/labels (TP/FN/labeled-FP/unexpected,
  recall/precision math, the `expected_total==0` N/A case).
- Corpus guard: for each labeled example, current recall >= `baseline.json` recall
  (epsilon for float); on failure, name the newly-missed expected finding(s).
- Determinism: `run_corpus` twice yields equal results.

## Behavioral rules

- Precision counts only the labeled surface (TP + labeled_FP); unlabeled emitted
  findings are reported as `unexpected`, excluded from precision (Principle II).
- A label referencing a missing example file → clear error (FR-010).
- The benchmark adds no change to analyzer output (Principle I/III; SC-005).

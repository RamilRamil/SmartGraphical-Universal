# Phase 0 Research: Benchmark Corpus

## D1. How does the runner obtain findings?

**Decision**: Call `web_api.analyze_all(path, language="solidity")` in-process and
read `report["findings"]`. No subprocess / CLI text parsing.

**Rationale**: `analyze_all` is the same pure facade used by the CLI and HTTP
layers; it returns JSON-safe finding dicts deterministically (sorted rule order,
no randomness). In-process is faster and avoids brittle stdout parsing.

**Alternatives considered**: shell out to `sg_cli.py ... json` — rejected (extra
process, stdout-cleanliness concerns, slower). Reaching into adapters directly —
rejected (bypasses the stable contract).

## D2. The benchmark match key

**Decision**: Match an emitted finding to a label by the **location projection**
of the shared identity: `match_key(finding) = (rule_id, type_name,
function_name)`, derived from the same finding fields `_finding_key` uses. Labels
are authored with exactly these three fields (+ a human note, + optional line for
readability).

**Rationale**: the full `_finding_key` includes `message` and `source_statement`,
which makes it precise but brittle — a trivial message reword would invalidate
every label. For a benchmark, "the same rule firing on the same function" IS the
same finding; matching at `(rule_id, type, function)` granularity is robust and
human-authorable while staying a projection of the one shared identity (no second
scheme). This is documented as the intended granularity.

**Alternatives considered**: full `_finding_key` hash — rejected (brittle to
message wording, high label-maintenance). A brand-new key — rejected (violates the
"one identity" principle).

**Edge**: if two distinct real findings share `(rule_id, type, function)` they
collapse to one match unit — documented; rare and acceptable for v1.

## D3. Label file format

**Decision**: One JSON file per example under `tests/benchmark/labels/<file>.json`:
```jsonc
{
  "example": "GuardedWithdrawFixture.sol",
  "expected": [
    { "rule_id": "withdraw_release_check", "type_name": "GuardedWithdrawFixture",
      "function_name": "withdraw", "note": "real reentrancy-order concern" }
  ],
  "false_positives": [
    { "rule_id": "unallowed_manipulation", "type_name": "GuardedWithdrawFixture",
      "function_name": "bid", "note": "amount is local, not economic state" }
  ]
}
```

**Rationale**: human-readable, reviewable, versioned, additive. `expected` =
ground-truth real findings; `false_positives` = emitted findings judged not real.

## D4. Precision / recall definitions

**Decision** (per rule and overall, over the **labeled surface**):
- True positive (TP): an `expected` label whose `match_key` is emitted.
- Miss (FN): an `expected` label not emitted → lowers recall.
- Labeled FP: a `false_positives` label whose `match_key` is emitted.
- Unexpected/unlabeled: an emitted finding matching neither list → surfaced and
  counted, **excluded from precision** (unjudged).
- **recall = TP / (TP + FN)** = expected found / expected total.
- **precision = TP / (TP + labeled_FP)** over the labeled surface.

**Rationale**: honest scoping — precision is only claimed where a human has
judged the emitted finding (Principle II). Unlabeled emissions are shown so the
maintainer can extend the labels, but never silently counted as right or wrong.

## D5. Baseline + recall guard

**Decision**: `tests/benchmark/baseline.json` records, per example, the recall
measured on the first green run (e.g. `{"GuardedWithdrawFixture.sol": {"recall": 1.0}}`).
The guard test asserts current recall >= baseline (minus a tiny epsilon for float)
per example, and names any newly-missed expected finding. Baseline is updated
intentionally (committed) when rules improve.

**Rationale**: prevents silent rule rot (FR-006) without hard absolute-score
gates; the maintainer owns the baseline.

## D6. Determinism

**Decision**: `analyze_all` is deterministic; the runner sorts findings, labels,
and report rows by stable keys. Re-runs produce identical metrics (FR-005/SC-003).

## D7. Label authoring bootstrap

**Decision**: Author the initial labels by running `analyze_all` on each chosen
example and **triaging** each emitted finding into `expected` (real) or
`false_positives` (not real); optionally add known **misses** to `expected` that
the tool does not emit (these record real gaps and set recall < 1). The first run
then fixes the baseline.

**Rationale**: bootstrapping from real output makes the corpus immediately useful
for precision and a recall baseline; it is the human judgment the spec requires
(Principle II), not auto-labeling.

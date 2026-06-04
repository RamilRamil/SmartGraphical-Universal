# Feature Specification: Labeled Benchmark Corpus + Precision/Recall Runner

**Feature Branch**: `014-rule-benchmark-corpus`

**Created**: 2026-06-02

**Status**: Draft

**Input**: Label real example contracts with ground-truth findings and run the analyzer against them to measure precision/recall per rule, so rule quality is a number, not a feeling — and so it can't silently regress.

## Context

SmartGraphical's rules are heuristic and evolve constantly, but their quality is judged by feel today: `docs/testing_*_coverage_matrix.md` are hand-written prose, and the real contracts under `examples/` are never measured against. This feature adds a **labeled benchmark**: human-authored ground truth for a curated set of examples, plus a runner that compares emitted findings to the labels and reports precision/recall, with a guard so recall cannot silently drop. It measures over the existing analyzer output and changes no rules.

The matching identity is the **same stable finding key** the diff and verdicts (feature 013) already use, so "the finding the benchmark expects" is exactly "the finding the tool emits."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Label an example's ground-truth findings (Priority: P1)

A maintainer records, for a benchmark example, the set of findings that are **real** (expected true positives) — by a stable identity — in a versioned label file kept with the corpus.

**Why this priority**: ground truth is the prerequisite for any measurement; without labels there is nothing to measure against. It is independently valuable as a documented, reviewable record of "what this contract should flag."

**Independent Test**: add a label file for one example; confirm it is picked up and its expected findings are enumerated by the runner.

**Acceptance Scenarios**:

1. **Given** an example contract, **When** a maintainer adds a label entry for an expected finding (by stable identity), **Then** the runner recognizes that example as labeled and lists its expected findings.
2. **Given** a label file with several expected findings, **When** it is loaded, **Then** all entries are parsed and addressable by their stable key.
3. **Given** a malformed label file, **When** the runner loads it, **Then** it reports a clear error naming the file rather than failing silently.

---

### User Story 2 - Measure recall and surface unexpected findings (Priority: P1)

The runner analyzes each labeled example, matches emitted findings to the labels by the shared stable key, and reports **recall** (labeled-expected findings that were found) per rule and overall, plus the count and list of emitted findings that are not in the labels ("unexpected").

**Why this priority**: recall + an unexpected-findings list is the core measurement and the MVP payoff — it tells the maintainer what the rules miss and what extra noise they produce.

**Acceptance Scenarios**:

1. **Given** an example with 5 expected findings of which the analyzer emits 4, **When** the runner runs, **Then** recall for that example is reported as 4/5 (80%) with the missed one listed.
2. **Given** the analyzer emits a finding not present in the labels, **When** the runner runs, **Then** that finding is listed as "unexpected" and counted.
3. **Given** multiple labeled examples, **When** the runner runs, **Then** it reports per-rule and overall recall aggregated across the corpus.
4. **Given** the same corpus and code, **When** the runner is run twice, **Then** the numbers are identical (deterministic).

---

### User Story 3 - Label known false positives to measure precision (Priority: P1)

Labels can also mark specific emitted findings as **known false positives** (not real issues). The runner then reports **precision** (of the findings the tool emits that are labeled real-or-false-positive, the fraction that are real), not just recall.

**Why this priority**: recall alone rewards over-flagging. Precision needs a human verdict on emitted-but-wrong findings; labeling known false positives makes precision measurable for the labeled surface.

**Acceptance Scenarios**:

1. **Given** an emitted finding labeled "false positive", **When** the runner runs, **Then** it is counted against precision (not as a true positive) and not reported as "unexpected/unlabeled".
2. **Given** an example with labeled true positives and labeled false positives, **When** the runner runs, **Then** precision = TP / (TP + labeled-FP) is reported per rule and overall.

---

### User Story 4 - Recall regression guard (Priority: P2)

A test fails if recall for a labeled example drops below a recorded baseline, so a rule change that loses a real finding is caught.

**Acceptance Scenarios**:

1. **Given** a recorded recall baseline for the corpus, **When** a change reduces recall below it, **Then** the guard test fails and names the now-missed expected finding(s).
2. **Given** recall meets or exceeds the baseline, **When** the guard runs, **Then** it passes.

---

### User Story 5 - Readable report (Priority: P3)

The runner emits a human-readable summary (text/markdown) and a machine-readable JSON of precision/recall per rule, per category, and overall.

**Acceptance Scenarios**:

1. **Given** a completed run, **When** the report is produced, **Then** it shows per-rule and overall precision/recall plus counts of expected/found/missed/unexpected/labeled-FP.
2. **Given** the JSON output, **When** consumed by automation, **Then** it is stable and parseable.

### Edge Cases

- An expected label whose finding the analyzer no longer emits → counted as a **miss** (lowers recall), listed by identity.
- An emitted finding matching neither an expected nor a false-positive label → **unexpected/unlabeled** (surfaced, excluded from precision since unjudged).
- Two labels resolving to the same stable key → treated as one (documented).
- An example with no findings emitted and none expected → recall is vacuously satisfied (reported as N/A, not 0/0 error).
- A label referencing an example file that no longer exists → clear error.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The benchmark MUST let a maintainer record, per example, expected (real) findings and known false-positive findings by a stable identity, in versioned label files.
- **FR-002**: The runner MUST match emitted findings to labels using the SAME stable finding key the diff/verdicts use (one identity across the system).
- **FR-003**: The runner MUST compute and report, per rule and overall: recall (expected found / expected total), and the list/count of unexpected (unlabeled) emitted findings.
- **FR-004**: The runner MUST compute and report precision over the labeled surface (true positives / (true positives + labeled false positives)) per rule and overall.
- **FR-005**: The runner MUST be deterministic — identical inputs and code produce identical metrics.
- **FR-006**: A regression guard MUST fail when corpus recall drops below the recorded baseline and identify the newly-missed expected finding(s).
- **FR-007**: The runner MUST produce both a human-readable report and a machine-readable summary.
- **FR-008**: The benchmark MUST NOT change rules, parsing, adapters, or analyzer output; it only measures (constitution Principle I/III).
- **FR-009**: Labels encode human ground truth; the system MUST NOT auto-generate or alter labels (Principle II).
- **FR-010**: Loading malformed or stale labels MUST produce a clear, file-named error, never a silent skip.

### Key Entities

- **Benchmark label set**: per example, the expected (real) findings and the known false-positive findings, each addressed by stable finding identity, plus a short human rationale.
- **Stable finding identity** (existing): the key derived from a finding's fields (rule_id + type + function + statement + message), shared with diff and verdicts.
- **Benchmark result**: per rule / per category / overall — expected, found (true positives), missed, unexpected, labeled-false-positive, with derived recall and precision.
- **Recall baseline**: the recorded minimum recall the guard enforces.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: At least 3 example contracts are labeled with ground truth, and the runner reports per-rule and overall recall + precision for them.
- **SC-002**: For a labeled example, the runner correctly identifies every missed expected finding and every unexpected emitted finding (verified against a hand-checked case).
- **SC-003**: Running the benchmark twice on the same code yields identical numbers (deterministic).
- **SC-004**: A deliberate change that drops a real finding makes the recall guard fail and names the missed finding.
- **SC-005**: The benchmark adds no change to analyzer output — all existing rule/finding tests still pass.
- **SC-006**: Precision and recall use the one shared finding identity, so a labeled finding is the same identity the tool emits and the diff/verdict layer matches.

## Assumptions

- Solidity examples first (that is what `examples/` mostly contains); the format is language-neutral so C/Rust can be added later.
- "Ground truth" is the maintainer's expert judgment per contract; the corpus starts small and curated (a few examples), not exhaustive.
- The recall baseline is recorded from the first green run and updated intentionally when rules improve.
- Precision is measured only over the labeled surface (true positives + labeled false positives); unlabeled emitted findings are surfaced but excluded from precision until judged.
- The runner uses the existing stable JSON finding output; no rule change is implied by a low score (improving scores is future work).

## Non-Goals

- Changing rules to chase benchmark scores (separate, later work).
- Machine-learning or automatic label generation.
- Exhaustive labeling of every emitted finding across all examples.
- Hard CI score-threshold gates beyond the recall-regression guard.
- Languages beyond what `examples/` currently provides (Solidity first).

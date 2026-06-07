---
description: "Task list for feature 014 — Labeled benchmark corpus + precision/recall runner"
---

# Tasks: Labeled Benchmark Corpus + Precision/Recall Runner

**Input**: Design documents from `specs/014-rule-benchmark-corpus/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED (constitution Principle VII; the benchmark is itself test/
traceability infrastructure).

**Repo root**: `SmartGraphical/`. Backend runs with `.venv/bin/python` (system
python is 3.9). Pure Python tooling — fully verifiable headless.

## Implementation status (2026-06-02)

**Fully implemented + verified (pure Python).** `benchmark/corpus.py`
(match_key / load_labels / evaluate / run_corpus) + 16 tests; 3 labeled examples
(GuardedWithdrawFixture, TokenRedeemFixture, StakingPoolFixture — a PROVISIONAL human-review seed);
`baseline.json` + recall guard (bite proven); `sg_benchmark.py` CLI (text +
deterministic `--json`). Full suite **471 passed, 0 failed** (analyzer output
unchanged, SC-005). Current corpus: overall recall 100%, precision 29%, with 5
unlabeled StakingPoolFixture findings surfaced for triage. Done: T001–T012.

- **Remaining**: T013 docs (README / NEXT_STEPS). The seed labels reflect the
  author's reading + KNOWN_QUIRKS and should be reviewed/extended by the
  maintainer (ground truth is theirs, per Principle II).

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: parallelizable (different files, no dependency on incomplete tasks)
- **[Story]**: US1–US5 from spec.md

---

## Phase 1: Setup

- [X] T001 Baseline + sanity: `.venv/bin/python -m pytest -q` is green; confirm `web_api.analyze_all('tests/fixtures/solidity/MinimalGuard.sol', 'solidity')` returns a `findings` list (the runner's source).

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ The pure metrics module backs every user story.**

- [X] T002 Create `smartgraphical/benchmark/__init__.py` and `smartgraphical/benchmark/corpus.py` with `match_key(finding)` = `(rule_id, evidences[0].type_name, evidences[0].function_name)`, `load_labels(path)`, `evaluate(findings, label_file)` (TP/FN/labeled_FP/unexpected + recall/precision), and `run_corpus(labels_dir, examples_dir, analyze)` (analyzer injected; deterministic sorted output) per `contracts/benchmark.md`.
- [X] T003 [P] Unit tests `tests/benchmark/test_benchmark.py` for `evaluate`/`match_key` on synthetic findings + labels: TP/FN/labeled_FP/unexpected counts, `recall = found/expected`, `precision = TP/(TP+labeled_FP)`, and the `expected_total == 0` → N/A case.

**Checkpoint**: deterministic metrics available and unit-tested.

---

## Phase 3: User Story 1 - Label an example's ground truth (Priority: P1) 🎯 MVP

**Goal**: versioned label files declare expected real findings and known false positives for >= 3 examples.

**Independent Test**: labels load and enumerate; malformed/stale labels error clearly.

- [X] T004 [US1] Author `tests/benchmark/labels/<example>.json` for >= 3 examples (e.g. GuardedWithdrawFixture.sol, StakingPoolFixture.sol, TokenRedeemFixture.sol) by running `web_api.analyze_all` and triaging each emitted finding into `expected` (real) or `false_positives` (not real), with a human `note`; optionally add known misses to `expected`.
- [X] T005 [US1] Tests in `tests/benchmark/test_benchmark.py`: `load_labels` rejects malformed JSON, a missing required field, and a label referencing a non-existent example file — each with a clear, file-named error (FR-010).

**Checkpoint**: a reviewable ground-truth corpus exists.

---

## Phase 4: User Story 2 - Measure recall + unexpected (Priority: P1)

**Goal**: per-rule and overall recall, plus the list of emitted-but-unlabeled findings.

**Independent Test**: on the authored corpus, recall and the unexpected list are correct and deterministic.

- [X] T006 [US2] Corpus test in `tests/benchmark/test_benchmark.py`: `run_corpus(labels_dir, 'examples', web_api.analyze_all)` reports per-rule and overall recall and lists `unexpected` findings on the authored corpus; running it twice yields equal results (determinism, SC-003).

**Checkpoint**: recall is measured across the corpus.

---

## Phase 5: User Story 3 - Measure precision via labeled false positives (Priority: P1)

**Goal**: precision over the labeled surface = TP / (TP + labeled_FP).

**Independent Test**: a labeled false positive lowers precision and is excluded from `unexpected`.

- [X] T007 [US3] Test: for an example whose labels include `false_positives`, `evaluate`/`run_corpus` report precision = TP/(TP+labeled_FP) per rule and overall, and the labeled false positives are NOT counted as `unexpected`.

**Checkpoint**: precision is measurable and honestly scoped.

---

## Phase 6: User Story 4 - Recall regression guard (Priority: P2)

**Goal**: a test fails if corpus recall drops below the recorded baseline.

- [X] T008 [US4] Record `tests/benchmark/baseline.json` = `{ "<example>": { "recall": <float> } }` from the first green `run_corpus`.
- [X] T009 [US4] Guard test in `tests/benchmark/test_benchmark.py`: current recall >= baseline per example (float epsilon); on failure name the newly-missed expected finding(s). Prove it bites by temporarily editing a label to expect an unemitted finding, confirm failure, then revert.

**Checkpoint**: rules cannot silently lose a labeled real finding.

---

## Phase 7: User Story 5 - Readable report (Priority: P3)

**Goal**: human-readable + machine-readable precision/recall report.

- [X] T010 [US5] Create `sg_benchmark.py` (thin CLI): run `run_corpus` over `tests/benchmark/labels`, print a per-rule / per-category / overall precision+recall table with missed and unexpected lists; `--json` prints the stable machine-readable aggregate.
- [X] T011 [US5] Verify per quickstart §3/§4: report renders; `--json` output is identical across two runs.

---

## Phase 8: Polish & Cross-Cutting

- [X] T012 [P] Full regression: `.venv/bin/python -m pytest -q` (0 failed, benchmark tests included); confirm analyzer/finding output is unchanged (SC-005, no rule change).
- [ ] T013 [P] Docs: note the benchmark + how to add labels in `README.md` / `NEXT_STEPS_PLAN.md`; cross-reference the manual `docs/testing_*_coverage_matrix.md`.

---

## Dependencies & Execution Order

- **Setup (T001)** → none.
- **Foundational (T002→T003)** → blocks all stories.
- **US1 (T004, T005)** → after Foundational.
- **US2 (T006)** → after US1 (needs labels).
- **US3 (T007)** → after US1 (needs false-positive labels).
- **US4 (T008→T009)** → after US2 (baseline from measured recall).
- **US5 (T010→T011)** → after Foundational + labels.
- **Polish (T012–T013)** → after all; parallel.

## Parallel Opportunities

- T003 (unit metrics tests) alongside T002 finalization.
- T012 and T013 — independent.

## Implementation Strategy

- **MVP = Foundational + US1 + US2** (labels + recall) — the first measurable
  signal; ship and review before precision/guard/CLI.
- **Pure-module-first**: corpus.py is unit-tested in isolation; labels, baseline,
  guard, and CLI are thin consumers. All Python — fully verifiable headless.

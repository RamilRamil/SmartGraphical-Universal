# Quickstart: Validate Feature 015 (Intra-Procedural Taint)

Run with `.venv/bin/python` (system python is 3.9).

## 1. Taint pass logic (US1) — unit

```bash
.venv/bin/python -m pytest tests/unit/test_taint_pass.py -q
```
Asserts on synthetic `NormalizedFunction`s: an input flowing into a sink with no
guard yields a `taint_path` with `guarded=False`; a guarded flow yields
`guarded=True`; no-flow yields `[]`; two runs are identical (deterministic).

## 2. Portable rule (US2) — unit + fixture

```bash
.venv/bin/python -m pytest tests/unit/test_tainted_input_rule.py -q
```
Asserts the rule emits exactly one medium-confidence finding (with source+sink
evidence) on the unguarded fixture, and is silent on the guarded / no-flow cases.

## 3. End-to-end on a fixture

```bash
# C tainted-flow fixture, run all rules:
.venv/bin/python sg_cli.py tests/fixtures/c/TaintedFlow.c all auditor json | \
  .venv/bin/python -c "import json,sys; d=json.load(sys.stdin); \
  print([f['rule_id'] for f in d.get('findings',[]) if f['rule_id']=='tainted_input_unguarded_sink'])"
```
Confirm the portable taint rule appears; confidence is `medium`.

## 4. requires_dataflow rules are invoked (US3)

```bash
.venv/bin/python -m pytest tests/unit/test_requires_dataflow_invoked.py -q
```
Enumerates the 5 `requires_dataflow` rules, asserts each is registered and its
`run(context)` completes without error (0 silently skipped), and that adding
taint facts does not change their output.

## 5. Exploration shows the path (US5)

```bash
.venv/bin/python sg_cli.py tests/fixtures/c/TaintedFlow.c all explore | grep -i taint
```
Confirm the function's source->sink path is listed.

## 6. Honesty + regression

```bash
.venv/bin/python -m pytest -q          # full suite green (SC-005, no rule output change)
```
Confirm no dataflow finding exceeds "medium" confidence, and the KNOWN_QUIRKS
entry documents the intra-procedural / FP-FN limits.

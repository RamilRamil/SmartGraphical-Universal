# Quickstart: Validate Feature 014 (Benchmark Corpus)

Run with `.venv/bin/python` (system python is 3.9).

## 1. Metrics logic (US2/US3) — unit

```bash
.venv/bin/python -m pytest tests/benchmark/test_benchmark.py -q
```
Asserts `evaluate` on synthetic findings/labels: recall = found/expected,
precision = TP/(TP+labeled_FP), missed and unexpected lists correct, and the
`expected_total == 0` N/A case.

## 2. Author / inspect labels (US1)

```bash
# See what a labeled example currently emits, to triage real vs false positive:
.venv/bin/python -c "from smartgraphical.services import web_api, history_service; \
  r=web_api.analyze_all('examples/SimpleAuction.sol','solidity'); \
  print(len(r['findings']),'findings'); \
  [print(f['rule_id'], f['evidences'][0].get('type_name'), f['evidences'][0].get('function_name')) for f in r['findings']]"
```
Then a label file `tests/benchmark/labels/SimpleAuction.sol.json` lists the real
ones under `expected` and the wrong ones under `false_positives`.

## 3. Run the benchmark report (US5)

```bash
.venv/bin/python sg_benchmark.py            # human-readable per-rule/overall P/R
.venv/bin/python sg_benchmark.py --json     # machine-readable aggregate
```
Confirm per-rule and overall recall/precision, plus missed and unexpected lists.

## 4. Determinism (US2 #4 / SC-003)

```bash
.venv/bin/python sg_benchmark.py --json > /tmp/b1.json
.venv/bin/python sg_benchmark.py --json > /tmp/b2.json
diff /tmp/b1.json /tmp/b2.json && echo "deterministic"
```

## 5. Recall guard (US4)

- The guard test passes at baseline. To prove it bites: temporarily edit a label
  to expect a finding the tool does not emit (or break a rule), run
  `pytest tests/benchmark/test_benchmark.py`, confirm it fails and names the
  missed finding. Revert.

## 6. No analyzer change (SC-005)

```bash
.venv/bin/python -m pytest -q   # full suite green; rule/finding output unchanged
```

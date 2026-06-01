# Quickstart: Validate Feature 011

Prerequisites: run from the repo root (`SmartGraphical/`) with the project venv
(`.venv/bin/python`); system `python3` is 3.9 and too old.

## 1. Reproduce the bug (before the fix)

```bash
.venv/bin/python -m pytest -q          # expect 17 failed (14 facade + 3 others)
```

```bash
# C analysis through the web facade currently raises:
.venv/bin/python -c "from smartgraphical.services import web_api; \
  print(web_api.analyze('tests/fixtures/c/MinimalTu.c', '1', language='c'))"
# -> WebApiError: analysis failed: ... parse_source() got an unexpected
#    keyword argument 'expand_local_imports'
```

## 2. Validate US1 — C and Rust web analysis restored

```bash
# Both should return a JSON-safe report (no TypeError/WebApiError):
.venv/bin/python -c "from smartgraphical.services import web_api; \
  r=web_api.analyze_all('tests/fixtures/c/MinimalTu.c', language='c'); \
  print('c ok', bool(r))"
.venv/bin/python -m pytest tests/unit/test_web_api_contract.py -q \
  tests/integration/test_http_rust_fixture_contract.py            # green
```

Acceptance: the C/Rust facade and bundle tests pass; Solidity output is unchanged.

## 3. Validate US2 — adapter contract conformance

```bash
.venv/bin/python -m pytest tests/unit/test_adapter_contract_conformance.py -q
```

Then temporarily break one adapter (remove `expand_local_imports` from
`c_base/adapter.py::parse_source`) and confirm the conformance test FAILS and
names `CBaseAdapterV0`. Revert.

## 4. Validate the green-suite triage

```bash
.venv/bin/python -m pytest \
  tests/integration/test_solidity_adapter_fixtures.py::SolidityAdapterFixtureTests::test_minimal_guard_phase5_shape_snapshot \
  tests/unit/test_c_adapter_model_graph.py -q          # all green
```

## 5. Validate US3 — CI gate

- Push the branch / open a PR and confirm the `tests` workflow runs `pytest` and
  the CLI JSON smoke on Python 3.10 and 3.12 and reports pass.
- Introduce a temporary failing test on a scratch branch and confirm the workflow
  reports failure (blocking).

## 6. Full green suite (SC-002)

```bash
.venv/bin/python -m pytest -q          # expect 0 failed
```

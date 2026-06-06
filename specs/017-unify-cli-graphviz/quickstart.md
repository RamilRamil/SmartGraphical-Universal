# Quickstart / Verification: Unify CLI graphviz and web renderers

## 0. Baseline

```bash
cd SmartGraphical
.venv/bin/python -m pytest -q          # expect 493 passed, 11 skipped
```

Capture the web graph payload baseline (SC-002 oracle):

```bash
PYTHONHASHSEED=0 PYTHONPATH=. .venv/bin/python - <<'PY' > /tmp/graph_payload_baseline.json
import json
from smartgraphical.services import web_api
fixtures = [
    ("tests/fixtures/solidity/WithdrawNoGuard.sol", "solidity"),
    ("tests/fixtures/c/MinimalIncludeTu.c", "c"),
    ("tests/fixtures/rust/SorobanViolations.rs", "rust"),
]
print(json.dumps({p: web_api.graph(p, l) for p, l in fixtures}, sort_keys=True, indent=2, default=str))
PY
```

## 1. Implement

Rewrite `core/graph.py::GraphBuilder.render` to draw from
`model_graph_to_dict(model)` with the GROUP_STYLE/EDGE_STYLE mapping; remove the
`func_X_Y`/`var_`/`obj_`/`sysfunc_` scheme.

## 2. Web payload unchanged (SC-002)

```bash
PYTHONHASHSEED=0 PYTHONPATH=. .venv/bin/python - <<'PY' > /tmp/graph_payload_after.json
import json
from smartgraphical.services import web_api
fixtures = [
    ("tests/fixtures/solidity/WithdrawNoGuard.sol", "solidity"),
    ("tests/fixtures/c/MinimalIncludeTu.c", "c"),
    ("tests/fixtures/rust/SorobanViolations.rs", "rust"),
]
print(json.dumps({p: web_api.graph(p, l) for p, l in fixtures}, sort_keys=True, indent=2, default=str))
PY
diff /tmp/graph_payload_baseline.json /tmp/graph_payload_after.json && echo "WEB PAYLOAD IDENTICAL ✅"
```

## 3. Parity + graceful degradation (SC-001, SC-005)

```bash
.venv/bin/python -m pytest tests/unit/test_graph_renderer_unified.py -q
```

## 4. Duplication gone (SC-004)

```bash
grep -nE 'func_\{|var_\{|sysfunc_|obj_\{' smartgraphical/core/graph.py \
  && echo "STILL PRESENT ❌" || echo "old func_X_Y scheme removed ✅"
```

## 5. Full regression (SC-003)

```bash
.venv/bin/python -m pytest -q          # expect ≥ 493 + new tests, 0 failed
```

## Done when

- Web payload identical (SC-002)
- Parity + graceful tests green (SC-001, SC-005)
- Old id scheme removed (SC-004)
- Full suite green (SC-003)

# Quickstart / Verification: Decompose the web_api god-module

A behaviour-preserving refactor is verified by proving "nothing observable
changed." Follow these steps.

## 0. Baseline (before touching code)

```bash
cd SmartGraphical
.venv/bin/python -m pytest -q        # expect: 486 passed, 11 skipped
wc -l smartgraphical/services/web_api.py   # baseline ~1485
```

Capture a graph/analyze snapshot for representative fixtures (throwaway file):

```bash
.venv/bin/python - <<'PY' > /tmp/web_api_baseline.json
import json
from smartgraphical.services import web_api
fixtures = [
    ("tests/fixtures/solidity/WithdrawNoGuard.sol", "solidity"),
    ("tests/fixtures/c/TaintedFlow.c", "c"),
]
out = {}
for path, lang in fixtures:
    out[path] = {
        "graph": web_api.graph(path, lang),
        "analyze_all": web_api.analyze_all(path, lang),
        "list_tasks": web_api.list_tasks(lang),
    }
print(json.dumps(out, sort_keys=True, indent=2))
PY
```
(Add a Rust bundle fixture and a Solidity/C bundle root to the list if available
in the tree for fuller coverage.)

## 1. Perform the move (per tasks.md)

Relocate code verbatim into `bundle_graph.py`, `task_catalog.py`,
`analyze_facade.py`; reduce `web_api.py` to explicit re-exports + `__all__`.

## 2. Re-run the snapshot and diff

```bash
.venv/bin/python - <<'PY' > /tmp/web_api_after.json
# (identical script as step 0)
import json
from smartgraphical.services import web_api
fixtures = [
    ("tests/fixtures/solidity/WithdrawNoGuard.sol", "solidity"),
    ("tests/fixtures/c/TaintedFlow.c", "c"),
]
out = {}
for path, lang in fixtures:
    out[path] = {
        "graph": web_api.graph(path, lang),
        "analyze_all": web_api.analyze_all(path, lang),
        "list_tasks": web_api.list_tasks(lang),
    }
print(json.dumps(out, sort_keys=True, indent=2))
PY
diff /tmp/web_api_baseline.json /tmp/web_api_after.json && echo "IDENTICAL ✅"
```

Expected: `IDENTICAL ✅` (SC-002).

## 3. Full suite + facade contract

```bash
.venv/bin/python -m pytest -q        # expect: 486 passed (unchanged) (SC-001)
.venv/bin/python -m pytest tests/unit/test_web_api_facade_reexports.py -q
```

## 4. No caller drift

```bash
# No import-statement changes anywhere except the new modules + web_api.py:
git diff --name-only | grep -v -E 'services/(web_api|bundle_graph|task_catalog|analyze_facade)\.py' \
  | grep -v 'tests/unit/test_web_api_facade_reexports.py' \
  | grep -v 'specs/016' || echo "no caller files changed ✅"
```

Expected: `no caller files changed ✅` (SC-005). (The pre-existing uncommitted
WIP under specs/005,008,010,012 and frontend is unrelated and ignored here.)

## 5. Size check

```bash
wc -l smartgraphical/services/web_api.py   # expect <= ~445 lines (>=70% drop, SC-003)
```

## Done when

- Snapshot diff is identical (SC-002)
- Full suite green at the same count (SC-001)
- Facade re-export test passes
- `web_api.py` ≤ 30% of its original size (SC-003)
- Each new module has a single responsibility (SC-004)
- No caller import changes (SC-005)

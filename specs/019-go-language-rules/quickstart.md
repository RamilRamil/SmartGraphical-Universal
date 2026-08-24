# Quickstart: Go Language Rules

## Validate locally

```bash
cd SmartGraphical
.venv/bin/python -m pytest tests/integration/test_http_go_fixture_contract.py -q
.venv/bin/python -m pytest tests/unit/test_adapter_contract_conformance.py -q
```

## CLI

```bash
.venv/bin/python sg_cli.py tests/fixtures/go/GoViolations.go 4 auditor json go
.venv/bin/python sg_cli.py tests/fixtures/go/GoViolations.go 0 auditor json go
```

## Web facade (Python)

```python
from smartgraphical.services import web_api

report = web_api.analyze("tests/fixtures/go/GoViolations.go", "4", language="go")
assert report["language"] == "go"
tasks = web_api.list_tasks("go")
assert tasks["tasks"][0]["id"] == "0"
```

## Catalog

- EN: `docs/go_language_rules_catalog.json`
- RU: `docs/rules_ru_go.md`
- Spec: `specs/019-go-language-rules/spec.md`

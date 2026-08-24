# Contracts for feature 020

The canonical schema lives outside this directory, at
`docs/contracts/analyzer-cli-v1.schema.json`, because consumers depend on it and
it ships inside the analyzer image. A per-feature copy would go stale.

Validated by `tests/unit/test_analyzer_cli_contract.py` against real CLI output,
using the dependency-free draft-07 subset validator in
`tests/support/json_schema.py`.

Contract summary:

- success document on stdout, exit 0;
- error document on stderr, stdout empty, exit 2 (usage), 3 (bad target),
  4 (analysis failed) or 1 (unclassified);
- `schema_version: 1`; additive fields keep the major version.

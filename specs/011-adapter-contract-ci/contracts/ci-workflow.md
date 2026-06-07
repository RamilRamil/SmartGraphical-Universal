# Contract: CI Workflow

**Location**: `.github/workflows/ci.yml` (new)

**Goal**: enforce the Principle VII gate — the suite is green on every push and
pull request, and a machine-readable CLI smoke confirms the public contract.

## Triggers

- `push` (all branches) and `pull_request`.

## Job: `tests`

- **Runner**: `ubuntu-latest`.
- **Python matrix**: `["3.10", "3.12"]` (floor + Docker-image version).
- **Steps**:
  1. Checkout.
  2. Setup Python `${{ matrix.python-version }}`.
  3. `pip install -r requirements.txt` (and `pytest`).
  4. `python -m pytest -q` — MUST exit 0 (FR-006, FR-007).
  5. CLI JSON smoke — positional args (`<file> <task> <mode> <format>`); use a
     single task so stdout is pure JSON (task `all` also renders the graph to
     stdout): `python sg_cli.py tests/fixtures/solidity/MinimalGuard.sol 11 auditor json`
     and assert the output parses as JSON with a report shape.
     (Note: the CLI uses positional `<format>`, not a `--format` flag — the
     README example is being corrected in this feature's Polish phase.)

## Pass/fail contract

- The job **fails** (blocking signal) if any test fails or the CLI smoke does not
  emit valid JSON (FR-006, SC-004).
- The job **passes** only when both the suite and the smoke succeed on both Python
  versions.

## Notes

- `graphviz` system package is NOT required: graph image rendering degrades
  gracefully (constitution Technology Constraints), and the JSON graph payload is
  produced by the serializer, not graphviz.
- Keep the workflow dependency-light; no Docker build in this gate (the Docker
  image is validated separately if/when needed).

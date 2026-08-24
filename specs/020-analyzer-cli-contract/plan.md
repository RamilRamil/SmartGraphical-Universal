# Plan: 020 Analyzer CLI contract

## Constitution check

- **III / VI (normalized model and stable contracts).** The CLI reuses
  `analyze_facade` rather than reimplementing analysis, so findings cannot
  diverge between the CLI, the HTTP API and the web UI. The new envelope is a
  presentation layer over the same reports.
- **VI (traceability).** Every report carries `tool.version` and
  `tool.rules_catalog_hash`, as the constitution requires of every scan.
- **VII (test gates).** Contract, determinism, stdout-purity and sandbox tests
  ship with the feature; the schema file is validated against real output.

## Approach

1. **`smartgraphical/services/provenance.py`** — one implementation of
   `tool_version()` and `rules_catalog_hash()`. The version no longer shells out
   to `git` (the analyzer image has neither git nor a `.git` directory, and a
   subprocess per run buys nothing). The hash now discovers `*_rules_catalog.json`
   under `docs/` instead of using a hardcoded three-file list that had silently
   fallen behind — it was missing the Solidity and Go catalogs.
   `history_service` delegates to it so a scan record and a CLI report of the
   same build agree.

2. **`smartgraphical/interfaces/cli/analyzer.py`** — argparse-based
   `analyze` subcommand, plus `smartgraphical/__main__.py` so
   `python -m smartgraphical` works. Analysis runs inside
   `contextlib.redirect_stdout` so engine prints cannot corrupt the JSON stream;
   the real stdout is written once, at the end, or never.

3. **Envelope.** A superset of `analyze_all`'s flat shape (so migrating from the
   old facade script is mechanical) plus `schema_version`, `tool`, and a
   top-level `graph` that is `null` unless `--graph` is passed. `duration_ms` is
   dropped, because it cannot be byte-stable; it goes to stderr instead. See
   KNOWN_QUIRKS Quirk 8.

4. **Determinism.** Findings sorted by content, graph nodes by `id`, edges by
   `(source, target, kind, label, id)`, JSON emitted with `sort_keys=True` and
   fixed separators. `PYTHONHASHSEED=0` is pinned in the image as belt and
   braces.

5. **`Dockerfile.analyzer`** — a separate file rather than a stage appended to
   `Dockerfile`, so that the web image stays the default build target and
   `docker compose` cannot pick up the wrong one. No frontend stage, no `pip
   install` (nothing to install), non-root uid 10001,
   `PYTHONDONTWRITEBYTECODE=1` so a read-only root filesystem is enough.

6. **Tests.** `tests/unit/test_analyzer_cli_contract.py` for the envelope,
   errors and determinism; `tests/integration/test_analyzer_sandbox.py` for the
   sandbox, in two layers — an in-process layer that removes sockets and runs
   from a read-only working directory (so CI without Docker still guards the
   property) and a Docker layer running the published command line.
   `tests/support/json_schema.py` implements the draft-07 subset the contract
   uses, so validating the schema adds no dependency.

7. **Publication.** `.github/workflows/analyzer-image.yml` builds the image,
   runs the sandbox test file against the candidate, and only then pushes to
   GHCR. A guarantee that is not re-checked at publish time is not a guarantee.

## Risks

- **Two CLIs.** Accepted and documented (Quirk 8). Folding the legacy one in
  would be a breaking change for human users with no benefit to this feature.
- **Base image not pinned by digest.** The tag is pinned and the dependency set
  is empty, so the realistic drift surface is the Python patch release. A
  `BASE_IMAGE` build arg is provided for consumers who need bit-reproducibility.
- **`additionalProperties: false` on the ok report.** Deliberate: it makes any
  new field a conscious schema change rather than an accident.

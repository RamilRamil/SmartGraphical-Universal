# Analyzer CLI — the batch integration surface

This is the supported way to run SmartGraphical as a static analyzer from a
script, a CI job, or another agent. It is a single command, one target in, one
JSON document out, no server.

If you are currently importing `smartgraphical.services.web_api` from your own
facade script: this page replaces that. `web_api` is an internal seam shared by
the HTTP layer and this CLI, and its dict shapes are refactored without notice.
The CLI envelope is versioned and covered by contract tests.

## Command

```
python -m smartgraphical analyze <path> [--mode auditor] [--language X] [--task N] [--graph] [--pretty]
```

| Flag | Meaning |
| --- | --- |
| `<path>` | A source file, or a bundle directory containing a bundle manifest. |
| `--mode` | `auditor` (default), `legacy`, or `explore`. Affects finding presentation only. |
| `--language` | Overrides extension-based detection: `solidity`, `c`, `rust`, `go`. |
| `--task` | Run one rule id instead of all of them. Default runs every rule. |
| `--graph` | Include the code graph. Omitted by default because it is much larger than the findings. |
| `--pretty` | Indent the JSON. Output stays deterministic either way. |

## Output contract

- **stdout carries exactly one JSON document and nothing else.** Every
  diagnostic goes to stderr, including anything the engine itself prints; the
  CLI captures engine stdout and redirects it. A tracked test injects a stray
  `print()` into the analysis path to prove this.
- The document is described by
  [`docs/contracts/analyzer-cli-v1.schema.json`](contracts/analyzer-cli-v1.schema.json)
  and carries `schema_version: 1`. Additive fields keep the major version; a
  removal or rename bumps it. A contract test validates real CLI output against
  that file, so the schema cannot drift away from the code.

Success envelope:

```json
{
  "schema_version": 1,
  "status": "ok",
  "tool": {"name": "smartgraphical", "version": "v1.2.3", "rules_catalog_hash": "b7c8..."},
  "artifact": "/audit/T.sol",
  "language": "solidity",
  "mode": "auditor",
  "task": "0",
  "rules_run": ["1", "2", "..."],
  "findings": [ ... ],
  "findings_count": 3,
  "graph": null
}
```

### The graph

`nodes` and `edges` are at a documented top level under `graph`, not buried in
`model_summary.graph`. `graph` is `null` unless `--graph` was passed — that is
how you tell "no graph requested" from "graph was empty".

```json
"graph": {
  "graph_schema_version": "1.1",
  "nodes": [{"id": "type:T", "group": "type", "...": "..."}],
  "edges": [{"source": "...", "target": "...", "kind": "..."}],
  "stats": {"types_count": 1, "functions_count": 2, "state_entities_count": 1,
            "guards_count": 0, "call_edges_count": 2}
}
```

Node objects are open by design: every node has `id` and `group`, and the rest of
the fields depend on the group. Treat unknown node fields as data to ignore, not
as a contract break.

## Errors are data

A run that did not produce an analysis writes an error envelope to **stderr**,
leaves stdout empty, and exits non-zero:

```json
{"schema_version": 1, "status": "error", "code": "invalid_path",
 "message": "source file or bundle not found: /audit/nope.sol",
 "tool": {"...": "..."}}
```

| Exit | Meaning | `code` |
| --- | --- | --- |
| `0` | Analysis ran. `findings_count` may be 0. | — |
| `1` | Unexpected failure the CLI could not classify. | `internal_error` |
| `2` | Usage error: bad flag, mode, language, or task id. | `invalid_arguments`, `invalid_mode`, `invalid_language`, `invalid_task` |
| `3` | The target does not exist or is not analyzable. | `invalid_path` |
| `4` | The analysis itself failed on a valid target. | `internal_error` |

**"Clean" versus "did not run" is exit code 0 with `findings_count: 0`, versus
any non-zero exit.** Never infer a clean result from an empty `findings` array
without checking the exit code — on failure there is no document on stdout at
all.

## Determinism

The same input against the same build produces byte-identical stdout.

- Findings are sorted by content (source file, task id, rule id, type, function,
  line, statement), not by the order rules happened to run.
- Graph nodes are sorted by `id`, edges by `(source, target, kind, label, id)`.
- JSON is emitted with sorted keys, ASCII escaping, and fixed separators.
- The analyzer path imports nothing outside the Python standard library, so
  there is no dependency set that can drift. The image installs no packages.
- No telemetry and no network access at runtime.

One deliberate exclusion: **wall-clock timing is not in the document.**
`duration_ms` cannot be byte-stable, so it is reported as a stderr diagnostic
line instead. If you need it, read stderr; if you diff runs, you get signal
instead of noise.

`tool.version` comes from `SG_TOOL_VERSION` (baked in at image build) and
`tool.rules_catalog_hash` fingerprints the shipped rule catalogs. Both change
across builds by design — that is what tells you a diff came from a tool change
rather than a code change.

## Container image

The analyzer image is built from `Dockerfile.analyzer` and is separate from the
web-service image. Its `ENTRYPOINT` is this CLI, so the target path is the first
argument.

```bash
docker run --rm --network none --cap-drop ALL --read-only \
  -v "$PWD/contracts:/audit:ro" \
  ghcr.io/<owner>/smartgraphical-analyzer:<tag> /audit/T.sol --mode auditor
```

Guarantees, each covered by `tests/integration/test_analyzer_sandbox.py`:

- runs with `--network none`, `--cap-drop ALL`, `--read-only`;
- runs as uid 10001, never root;
- writes nothing to the mounted target, which can stay `:ro`;
- repeated runs are byte-identical.

The publish workflow (`.github/workflows/analyzer-image.yml`) runs that same test
file against the candidate image and refuses to push if any guarantee is gone.

Building it yourself:

```bash
docker build -f Dockerfile.analyzer --build-arg SG_TOOL_VERSION=v1.2.3 \
  -t smartgraphical-analyzer:v1.2.3 .
```

For a bit-reproducible build, pin the base image by digest with
`--build-arg BASE_IMAGE=python:3.12-slim@sha256:<digest>`.

`BASE_IMAGE` accepts any base, including one that already defines
`SG_TOOL_VERSION`. The build arg still wins, and with no build arg you get the
honest `analyzer-unversioned` placeholder rather than a value leaked from the
base -- so `tool.version` always describes the build in front of you. Covered by
`AnalyzerImageProvenanceTests`.

## Relationship to the other entry points

| Entry point | Audience | Stability |
| --- | --- | --- |
| `python -m smartgraphical analyze` | scripts, CI, agents | versioned contract |
| `python sg_cli.py <file> <task> ...` | humans at a terminal | legacy positional args, text output |
| `python sg_web.py` + HTTP API | the web UI | HTTP schema |
| `smartgraphical.services.web_api` | internal | **no stability guarantee** |

All of them run the same analysis service, so findings do not differ between
them.

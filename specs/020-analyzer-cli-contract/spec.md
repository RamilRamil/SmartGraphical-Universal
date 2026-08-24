# Feature 020: Analyzer CLI contract for batch consumers

## Problem

The only way to embed SmartGraphical in an automated pipeline was to import
`smartgraphical.services.web_api` from a hand-written facade script and build a
private image around it. At least one consumer (an audit agent running the
engine in an isolated container) did exactly that.

That arrangement fails both sides:

- the consumer's parser is coupled to the shape of internal dicts, in particular
  the path `graph -> model_summary -> graph -> nodes/edges`, which was never a
  contract;
- the project cannot see who depends on that shape, so a routine refactor of
  `web_api` breaks a downstream integration silently.

## Findings from the reported observations

The consumer's report was verified against the source before designing
anything. Three of four observations held; one did not.

| Observation | Verdict |
| --- | --- |
| No single-shot entry point | **Partly wrong, right in effect.** `smartgraphical/interfaces/cli/main.py` exists and `sg_cli.py` invokes it, but the package exposes no `__main__`, so `python -m smartgraphical` fails; the module is invisible to `pkgutil.iter_modules`, which lists packages, and `sg_cli.py` is a top-level script, not a package module. More importantly, that CLI is unusable for batch work regardless: it prints findings as text, its JSON mode omits the findings themselves (only `findings_count`), it prompts interactively when the task argument is absent, and it prints errors to stdout. |
| Container runs as root | **Confirmed**, and inherent to the web-service image, which was the only image. |
| Errors only via exception | **Confirmed.** Stable codes exist in `web_support.py` and `WebApiError.to_dict()` already produces the right shape, but nothing serialized it at a process boundary. |
| Asymmetric result shapes | **Confirmed.** `analyze_all` returns a flat envelope; `graph` nests the payload under `model_summary.graph`. |
| Sandbox-readiness | **Confirmed as an existing asset.** Analysis completes with `--network none --cap-drop ALL --read-only` and a read-only target mount. The analyzer path imports nothing outside the standard library. |
| Determinism | **Already holds for content.** Findings and graph node order are stable across `PYTHONHASHSEED` values (feature 015 fixed the last source of drift). The only non-reproducible field is `duration_ms`. |

## Requirements

- **FR-1** A single command analyzes one target and prints one JSON document to
  stdout without starting a server.
- **FR-2** stdout carries JSON and nothing else. Engine output is redirected to
  stderr rather than merely assumed absent.
- **FR-3** The envelope carries `schema_version`; a JSON Schema is published in
  the repository and validated against real output by a test. Graph `nodes` and
  `edges` are raised to a documented top level.
- **FR-4** Failures produce a JSON error envelope on stderr and a non-zero exit
  code, with distinct codes per failure class. "Analysis ran, no findings" is
  distinguishable from "analysis did not run".
- **FR-5** An analyzer image separate from the web service, whose `ENTRYPOINT`
  is the CLI, runs under `--network none --cap-drop ALL --read-only` as a
  non-root user, writes nothing to the mounted target, and is published to a
  registry with tags.
- **FR-6** A test exercises those sandbox flags and fails if the engine ever
  needs network, writes, or root.
- **FR-7** Identical input against an identical build produces byte-identical
  stdout.

## Out of scope

- Changing `sg_cli.py`. Its positional arguments and text output stay as they
  are for human users.
- Changing the HTTP API or `web_api` shapes. Existing consumers of those are
  unaffected; `web_api` remains explicitly unsupported for direct integration.
- Bundle-format changes. The CLI accepts the existing bundle-directory form.

## Acceptance

```bash
docker run --rm --network none --cap-drop ALL --read-only \
  -v "$PWD/contracts:/audit:ro" <analyzer-image> /audit/T.sol --mode auditor
```

prints a valid document on stdout and exits 0; the same command with a
nonexistent path prints an error document on stderr, leaves stdout empty, and
exits non-zero.

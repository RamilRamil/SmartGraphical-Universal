# SmartGraphical

SmartGraphical is an auditor-centric logical vulnerability scanner with a
graphical code model. Two languages are supported today:

- **Solidity** (original domain, 11 rule tasks).
- **C / Solana node client** (second-language PoC, 20+ rules across memory,
  concurrency, validation, portability and Rust semantic-gap categories).

The tool can be used as a CLI or as a local web application with upload,
history, diff and interactive graph visualization.

## Origin and this fork

The foundation comes from the original project by **[mohamadpishdar](https://github.com/mohamadpishdar)**:
[github.com/mohamadpishdar/SmartGraphical](https://github.com/mohamadpishdar/SmartGraphical). Thank you for the initial idea and implementation.

This repository **continues, improves, and extends** that work (robustness,
features, checks, and documentation evolve over time). The goal is to keep
the same overall approach while making the tool more useful and maintainable.

The upstream project did not include a standalone `LICENSE` file; this README
keeps **clear attribution** to the original author. If a license is added
upstream later, this fork should stay aligned with it.

## Documentation in this fork

- `PROJECT_VISION.md` - intent and direction (auditor-centric, pragmatic parsing).
- `NEXT_STEPS_PLAN.md` - phased roadmap (CLI, tests, web layer, second language).
- `KNOWN_QUIRKS.md` - intentional heuristic trade-offs and parser limitations.
- `docs/graph_schema_logic_c.md` - C graph payload: target contract vs `c_base` implementation matrix.

## Quick start

### Option A. Docker (recommended for the web UI)

```bash
docker compose up --build
```

- Web UI and API on `http://127.0.0.1:8765`.
- Artifacts, database and graph payloads are persisted under `./workspace`
  (mounted from the host).
- Supported env vars (see `docker-compose.yml`):
  `SG_HTTP_HOST`, `SG_HTTP_PORT`, `SG_WORKSPACE`, `SG_DATABASE`,
  `SG_TOOL_VERSION`.

### Option B. Local Python virtualenv

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python sg_web.py          # web API + static frontend on :8765
.venv/bin/python sg_cli.py <file>   # single-file CLI analysis
```

For frontend development (hot-reload):

```bash
cd frontend
npm install
npm run dev                          # Vite dev server, proxies API to :8765
```

### Option C. CLI only

The CLI works without FastAPI / Node.

```bash
python3 sg_cli.py SimpleAuction.sol                # auto-detect language, run all tasks
python3 sg_cli.py SimpleAuction.sol 8              # single task
python3 sg_cli.py SimpleAuction.sol all auditor    # all tasks, auditor output
python3 sg_cli.py contracts/parser.c all explore   # C file, explore mode
python3 sg_cli.py SimpleAuction.sol all auditor --format json
```

Output modes:

- `legacy` - original alert-style output.
- `auditor` - findings with category, portability, confidence, evidence and
  remediation hint (default).
- `explore` - normalized model summary before findings or the graph.

Output formats: `text` (default) or `json` (stable contract, suitable for CI).

## Web UI

The web application is a single local researcher's tool served from `sg_web.py`
(Uvicorn + FastAPI). It exposes the following pages:

- **Upload** - drag-and-drop or file picker with client-side validation
  (size, extension, language auto-detection), then runs a chosen task/mode.
- **Artifacts** - list of uploaded files, opens the artifact detail page.
- **Artifact detail** - metadata, per-artifact scan history, a "run new scan"
  form, and a "compare two scans" selector.
- **History** - global list of non-deleted scans, supports soft-delete via
  confirmation modal; can be filtered by artifact id.
- **Scan detail** - scan metadata, error banner for failed runs, and two tabs:
  - `Findings` - grouped list with confidence filter.
  - `Graph` - interactive Cytoscape.js view, enabled only for `task = all`.
- **Diff** - side-by-side comparison of two scans of the same artifact:
  added / removed findings plus an unchanged count.

All state is persisted in a local SQLite database (`workspace/smartgraphical.db`
by default). Findings and graph payloads are stored as JSON on disk under
`workspace/scans/<scan_id>/`.

## Graph visualization

Activated on `Scan detail -> Graph` when the scan was run with task `all`.

- Backend serializer: `smartgraphical/services/serializers.py::model_graph_to_dict`.
- Produces a Cytoscape-ready `{nodes, edges}` payload.
- Node groups:
  - `type` - compound parent per contract / translation unit,
  - `function` - child of its type; border color encodes Solidity modifiers
    (`payable`, `view`, `onlyOwner`, etc.; visibility keywords are skipped).
    If no styling modifiers exist, entrypoints keep an orange border.
  - `state` - state entities / globals,
  - `event` - declared events (`emit` edges use a distinct edge color),
  - `external` - syscalls or unresolved targets (fallback node).
- Edges preserve `edge_kind` and `label` from `NormalizedCallEdge` and always
  reference existing node ids. Edge color / line style distinguishes
  `state_to_function`, `function_to_event`, `function_to_object` (dashed),
  `function_to_system` (dotted), and `cross_type_call`.
- Frontend renders with `cytoscape` + `cytoscape-cose-bilkent` layout.
- Toolbar: node/edge counters, legend, **Fit** (zoom-to-fit) and
  **Export PNG** (via `core.png`). Click on a node highlights its connected
  edges and shows a metadata panel.

Scans created before the W9 graph work do not include `nodes/edges` in the
stored payload; they fall back to a hint asking to re-run the analysis.

## C / Solana node client support

The second-language PoC lives under `smartgraphical/adapters/c_base/` and
targets both language-level and domain-level issues in Solana's C node client.

Graph-oriented extraction includes regex call edges, `struct` / `typedef struct` workspace nodes, template `#include "*.c"` **tile→`inc:*`** links (one `function_to_include_template` edge per include node), and heuristic `function_to_workspace` targets; optional `struct_field_access_hints` live on `findings_data.function_facts`, not in the Cytoscape JSON payload. The graph JSON adds C-profile **`exploration_hints`** (counts, large-graph warning above configurable thresholds) and per-function **`heuristic_callees_ordered`** when call-order data is present; unresolved callees use **`external:<class>:<symbol>`** with prefix-based `class` heuristics (`SYS_`/`__NR_`, `fd_`, `pthread_`, etc.).

Rule catalog: `docs/c_node_rules_catalog.json` (20+ rules, 100-series ids).

Categories covered today include:

- **memory** - use-after-free, double free, uninitialized reads, unaligned
  access, struct padding leakage.
- **concurrency** - lock ordering, missing unlock on error path, unprotected
  shared state.
- **validation** - unchecked error codes, untrusted network input reaching
  critical state.
- **arithmetic** - signed integer overflow, unsigned wrap, division rounding
  relative to Rust semantics.
- **portability / semantic-gap** - unspecified evaluation order, implicit
  integer promotion, assumptions that do not hold after a Rust rewrite.
- **solana-specific** - packet handlers, consensus state paths, persistence
  and recovery consistency.

Rules marked `requires_dataflow: true` in the catalog are registered but not
executed at PoC confidence today; they are reserved for the future
interprocedural dataflow phase.

## Internal architecture

```text
smartgraphical/
  core/
    model.py            # NormalizedAuditModel and friends
    findings.py         # Finding, FindingEvidence
    engine.py           # RuleEngine, rule registration
    graph.py            # GraphBuilder (graphviz renderer)
    rules/              # rule runners grouped by category
  adapters/
    solidity/           # SolidityAdapterV0 + reader + helpers
    c_base/             # C adapter (PoC) + Solana node domain rules
  services/
    analysis_service.py # orchestrates adapter + RuleEngine + GraphBuilder
    web_api.py          # pure-Python facade: analyze, analyze_all, graph, list_tasks
    serializers.py      # JSON-safe serializers, incl. model_graph_to_dict
    history_service.py  # artifacts, scans, diff, tool_version / rules hash
    storage/            # SqliteStore + artifact/scan repositories
  interfaces/
    cli/                # sg_cli.py -> interfaces.cli.main
    http/               # FastAPI routes, schemas, app factory
docs/
  c_node_rules_catalog.json
  c_node_rules_catalog.schema.json
frontend/
  src/
    api/                # typed client + TanStack Query hooks
    components/         # GraphView, ScansTable, FindingCard, RunScanForm, ...
    pages/              # Upload, History, ArtifactDetail, ScanDetail, Diff
workspace/              # runtime (created at first use): SQLite + per-scan json
sg_cli.py               # CLI entrypoint
sg_web.py               # Uvicorn launcher
Dockerfile              # multi-stage build (frontend + backend)
docker-compose.yml      # one-command deployment
requirements.txt        # fastapi, uvicorn, python-multipart
```

Key runtime contracts:

- `web_api.*` functions are pure and return JSON-safe dicts; the HTTP layer
  is a thin wrapper, the CLI reuses the same facade.
- Scans record `tool_version` (from `SG_TOOL_VERSION` env var or `git rev-parse`)
  and `rules_catalog_hash`, so historical results remain traceable.
- Diff uses a stable composite key over finding fields to detect added /
  removed / unchanged findings across runs of the same artifact.

## Rule groups

**Solidity (`smartgraphical/adapters/solidity/`):**

- `NamingAndConsistency` - Tasks `1`, `10`.
- `StateAndMutation` - Tasks `2`, `4`, `11`.
- `FlowAndOrdering` - Tasks `6`, `8`, `9`.
- `ComputationAndEconomics` - Tasks `3`, `5`, `7`.
- `VisualizationOnly` - Task `12` (graph only).

CLI task `all` (alias `13`) runs all rules `1`-`11` and then renders the graph.

**C / Solana node client (`smartgraphical/adapters/c_base/`):**

See `docs/c_node_rules_catalog.json` for the canonical list of rule ids,
titles, categories, portability and confidence labels. Tasks are exposed
through `GET /api/languages/c/tasks` and the same task selector in the web
UI and the CLI.

## Portability direction

The long-term direction is to keep the review principle portable across
languages such as Rust and C++. The current codebase defines a normalized
layer (`NormalizedAuditModel`) and a second-language target (C / Solana
node). New adapters should:

- extract `FunctionLike`, `StateEntity`, `CallSite`, `Guard`, `Mutation`,
- run at least two portable rules on the normalized model,
- render the same overview graph from the normalized model.

# SmartGraphical checks the Solidity tasks below:

Task 1: The signatures associated with the function definitions in every function of the smart contract code must be examined and updated if the contract is the outcome of a rewrite or update of another contract. If this isn't done, the contract may have a logical issue, and information from the previous signature may be given to the functions using the programmer's imagination. This inevitably indicates that the contract code contains a runtime error.

Task 2: In the event that the developer modifies contract parameters, such as the maximum fee or user balance, or other elements, like totalSupply, that are determined by another contract. This could be risky and result in warnings being generated. Generally speaking, obtaining any value from a source outside the contract may have a different value under various circumstances, which could lead to a smart contract logical error. For instance, the programmer might not have incorporated the input's fluctuation or range into the program logic

Task 3: The quantity of collateral determines one of the typical actions in DeFi smart contracts, in addition to stake and unstake. Attacks like multiple borrowing without collateral might result from logical mistakes made by the developer when releasing this collateral, determining the maximum loan amount that can be given, and determining the kind and duration of the collateral encumbrance

Tasks 3 and 5 and 9: When a smart contract receives value, like financial tokens or game points (from staking assets, depositing points, or depositing tokens), it must perform a logical check when the assets are removed from the system to ensure that no user can circumvent the program's logic and take more money out of the contract than they are actually entitled to.

Tasks 2 and 4: All token supply calculations must be performed accurately and completely. Even system security and authentication might be taken into account, but the communication method specification is entirely incorrect. For instance, one of the several errors made by developers has been the presence of a function like burn that can remove tokens from the pool or functions identical to it that can add tokens to the pool. To determine whether this is necessary in terms of program logic and whether other supply changes are taken into account in this computation, these conditions should be looked at. No specific function is required, and burning tokens can be moved to an address as a transaction without being returned.

Task 2 and 5 and 9: There are various incentive aspects in many smart contracts that defy logic. For instance, if the smart contract has a point system for burning tokens, is it possible to use that point in other areas of the contract? It is crucial to examine the income and spending points in this situation. For instance, the developer can permit spending without making sure the user validates the point earning. The program logic may be abused as a result of this.

Task 6: The code's error conditions need to be carefully examined. For instance, a logical error and a serious blow to the smart contract can result from improperly validating the error circumstances. Assume, for instance, that the programmer uses a system function to carry out a non-deterministic transport, but its error management lacks a proper understanding of the system state. In the event of an error, for instance, the coder attempts to reverse the system state; however, this may not be logically sound and could result in misuse of the smart contract by, for instance, reproducing an unauthorized activity in the normal state.

Task 7: Logical errors can result from any complicated coding calculations. For instance, a cyber attacker may exploit the program logic by forcing their desired computation output if the coder fails to properly analyze the code output under various scenarios.

Tasks 8 and 9: A smart contract's execution output might be impacted by the sequence in which certain procedures are carried out. The developer measuring or calculating the price of a token (or anything similar) and then transferring the asset at a certain time period is one of the most prevalent examples of this kind of vulnerability. Given that the attacker can manipulate the market through fictitious fluctuations, this is a logical issue. Thus, this gives the attacker the ability to remove the asset from the agreement.

Task 10: In a smart contract, using names that are spelled similarly to one another may cause logical issues. For instance, the coder might inadvertently substitute one of these definitions for another in the contract, which would be undetectable during the coder's initial tests. There is a chance that a cybercriminal will take advantage of this scenario.

Task 11: A smart contract's function that can be called fully publicly and without limitations may be risky and necessitate additional research from the developer if it modifies variables, delivers inventory, or does something similar

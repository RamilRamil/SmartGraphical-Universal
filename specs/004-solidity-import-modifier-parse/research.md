# Research: Solidity Import Graph and Override Modifier Parsing

## Decision 1: Contract-level import source resolution

**Decision**: In `model_graph_to_dict`, when building `import_dependency` edges, if `source_name == source_type`, resolve source to `_type_id(source_type)`.

**Rationale**: Unused imports intentionally use contract name as pseudo-caller; serializer must map that to the type compound, not spawn `external:{ContractName}`.

**Alternatives considered**: Change adapter to use sentinel `__imports__` function name — rejected as wider API change.

## Decision 2: Parenthesis-aware ext_params tokenization

**Decision**: Replace `ext_params.strip().split(' ')` with depth-aware splitter in `ContractReader`.

**Rationale**: Matches existing `_split_arguments` pattern in adapter; fixes `override(...)`, `reinitializer(...)`, and similar in one place.

**Alternatives considered**: Post-merge in serializer only — rejected; raw modifiers pollute findings/rules downstream.

## Decision 3: Modifier graph filtering

**Decision**: Exclude `_SOLIDITY_SIGNATURE_MODIFIERS` and tokens starting with `override(` from modifier node / ring candidate sets in serializer.

**Rationale**: Visibility and override annotations are not user-defined modifiers; `nonReentrant` etc. remain.

**Alternatives considered**: Strip at adapter `build_normalized_model` — rejected to keep normalized model faithful to source for other consumers.

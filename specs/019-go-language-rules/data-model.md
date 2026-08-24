# Data Model: Go Adapter

**Feature**: 019-go-language-rules

## NormalizedArtifact

| Field | Value |
|-------|-------|
| `language` | `"go"` |
| `adapter_name` | `GoAdapterV0` |

## NormalizedType

One synthetic type per file: basename of source (e.g. `GoViolations`), `kind=go_package`.

**State entities**: `struct` types parsed via `type Name struct {`.

## NormalizedFunction

Extracted from:
- `func Name(...)` top-level functions
- `func (recv Type) Name(...)` methods

**function_facts** (additive, in `findings_data.function_facts`):

| Key | Meaning |
|-----|---------|
| `value_receiver` | Method receiver is value `(s Type)` not pointer |
| `pointer_receiver` | Method receiver is `(s *Type)` |
| `receiver_type` | Receiver type name |
| `is_test_func` | Name prefix `Test` / `Fuzz` / `Benchmark` |
| `package_name` | Parsed `package` clause |

**exploration_statements**: semicolon-split body chunks for pattern rules.

## Call Edges

Heuristic `identifier(` tokens in body → `function_to_function` when callee is
another extracted function in the same file.

## Rule Registry

18 entries; see `docs/go_language_rules_catalog.json` for `rule_id` ↔ `task_id`.

# Contract: Go Adapter and Rule Registry

**Feature**: 019-go-language-rules

## Language ID

- CLI / HTTP: `go`
- File extension: `.go`
- Case: lowercase only

## Adapter

```text
GoAdapterV0.parse_source(source_path, *, expand_local_imports=True) -> AnalysisContext
```

- `expand_local_imports`: no-op (documented).
- `AnalysisContext.language`: `"go"`.
- `normalized_model.artifact.language`: `"go"`.

## Rule Registry

```text
build_go_rule_registry() -> dict[str, RuleSpec]
```

| Task | rule_id |
|------|---------|
| 1 | sparse_array_initialization |
| 2 | multi_param_type_sharing_obscurity |
| 3 | blank_identifier_index_discard |
| 4 | closure_loop_variable_capture |
| 5 | value_receiver_mutation_lost |
| 6 | unbounded_loop_missing_cancel |
| 7 | nil_map_write_panic |
| 8 | slice_aliasing_sensitive |
| 9 | defer_argument_eager_eval |
| 10 | typed_nil_interface_return |
| 11 | variable_shadowing_stale_err |
| 12 | parallel_subtest_loop_capture |
| 13 | build_tag_hidden_security_tests |
| 14 | table_driven_missing_edge_cases |
| 15 | external_test_package_blackbox_gap |
| 16 | compiler_pragma_noescape |
| 17 | compiler_pragma_nosplit |
| 18 | compiler_pragma_linkname |

Meta task **`0`** (alias **`all`**) runs tasks 1-18.

## HTTP

- `GET /api/languages/go/tasks` — 200 with 19 tasks (0 + 1-18).
- `POST` analyze with `language=go` on `.go` artifact — 200 findings report.

## Non-Goals

- `go.mod` / module graph resolution in this contract version.

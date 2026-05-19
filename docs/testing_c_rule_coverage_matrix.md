# C registry coverage (tasks 1-20)

Source of truth for rule runners: `smartgraphical/adapters/c_base/adapter.py` (`build_c_rule_registry`).

Machine-readable checklist (phase 4): `tests/fixtures/c_task_coverage.json`.

Drift gate: `tests/unit/test_c_task_coverage_declared.py` (also checks `web_api.list_tasks("c")`: meta id `0` first).

Integration (`.c` fixtures under `tests/fixtures/c/`):

| Fixture | Purpose |
|---------|---------|
| `MinimalTu.c` | Adapter: static + external linkage; HTTP `task: 0` or `all` shape (`test_http_c_fixture_contract.py` if FastAPI installed). |
| `FloatToUintCast.c` | Adapter + pipeline: expect task **1** (`non_saturating_float_cast`) firing on float-like operand heuristics (e.g. literal `1.0`). |
| `MinimalStructTu.c` | `struct` tag + heuristic call edge (`widget_sum` -> `getv`); graph / adapter tests. |
| `MinimalIncludeTu.c` | Quoted `#include "*.c"` -> `inc:*` + **одно** `function_to_include_template` на пару (tile, `inc`) за TU. |
| `MinimalIncludeAngleTu.c` | Angle `#include <.../*.c>`. |
| `MinimalIncludeDupBasename.c` | Two paths, same basename -> `inc:pool.c` and disambiguated `inc:pool.c~*`. |

C PoC adapter is lexer-light: rule **1** uses text heuristics for float-like operands only, not arbitrary `(ulong)` casts.

Tests: `tests/integration/test_c_adapter_fixtures.py`, `tests/integration/test_full_pipeline_c_fixtures.py`.

| task_id | rule_id (slug) | Unit tests (synthetic model) |
|--------|----------------|------------------------------|
| 1 | non_saturating_float_cast | `tests/unit/test_c_rules.py` |
| 2 | unsafe_shift_external_exponent | same |
| 3 | unchecked_return_sensitive | same |
| 4 | shared_mem_uaf_pool | same |
| 5 | incomplete_reserved_account_list | same |
| 6 | sysvar_decode_callback_type_mismatch | same |
| 7 | bitwise_flag_normalization_mismatch | `tests/unit/test_c_rules_batch2.py` |
| 8 | quic_invisible_frame_limit | same |
| 9 | quic_handshake_eviction_missing | same |
| 10 | bank_lifecycle_refcount_concurrency | `tests/unit/test_c_rules_batch3.py` |
| 11 | io_uring_submission_race_funk | `tests/unit/test_c_rules_batch4.py` |
| 12 | alt_resolution_window_mismatch | `tests/unit/test_c_rules_batch3.py` |
| 13 | keyswitch_atomicity_violation | `tests/unit/test_c_rules_batch4.py` |
| 14 | bls_aggregate_rogue_key_check | `tests/unit/test_c_rules_batch3.py` |
| 15 | unsupported_program_id_divergence | `tests/unit/test_c_rules_batch4.py` |
| 16 | signed_integer_overflow_consensus | `tests/unit/test_c_rules_batch5.py` |
| 17 | unspecified_evaluation_order_side_effects | same |
| 18 | protocol_struct_padding_mismatch | same |
| 19 | division_rounding_divergence | same |
| 20 | unaligned_memory_access_ebpf | same |

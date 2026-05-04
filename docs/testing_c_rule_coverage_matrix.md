# C registry coverage (tasks 101-120)

Source of truth for rule runners: `smartgraphical/adapters/c_base/adapter.py` (`build_c_rule_registry`).

Machine-readable checklist (phase 4): `tests/fixtures/c_task_coverage.json`.

Drift gate: `tests/unit/test_c_task_coverage_declared.py` (also checks `web_api.list_tasks("c")` ids + trailing `all`).

Integration (`.c` fixtures under `tests/fixtures/c/`):

| Fixture | Purpose |
|---------|---------|
| `MinimalTu.c` | Adapter: static + external linkage; HTTP `task: all` shape (`test_http_c_fixture_contract.py` if FastAPI installed). |
| `FloatToUintCast.c` | Adapter + pipeline: expect task **101** (`non_saturating_float_cast`) firing on float-like operand heuristics (e.g. literal `1.0`). |
| `MinimalStructTu.c` | `struct` tag + heuristic call edge (`widget_sum` -> `getv`); graph / adapter tests. |
| `MinimalIncludeTu.c` | Quoted `#include "*.c"` -> `inc:*` + **одно** `function_to_include_template` на пару (tile, `inc`) за TU. |
| `MinimalIncludeAngleTu.c` | Angle `#include <.../*.c>`. |
| `MinimalIncludeDupBasename.c` | Two paths, same basename -> `inc:pool.c` and disambiguated `inc:pool.c~*`. |

C PoC adapter is lexer-light: rule **101** uses text heuristics for float-like operands only, not arbitrary `(ulong)` casts.

Tests: `tests/integration/test_c_adapter_fixtures.py`, `tests/integration/test_full_pipeline_c_fixtures.py`.

| task_id | rule_id (slug) | Unit tests (synthetic model) |
|--------|----------------|------------------------------|
| 101 | non_saturating_float_cast | `tests/unit/test_c_rules.py` |
| 102 | unsafe_shift_external_exponent | same |
| 103 | unchecked_return_sensitive | same |
| 104 | shared_mem_uaf_pool | same |
| 105 | incomplete_reserved_account_list | same |
| 106 | sysvar_decode_callback_type_mismatch | same |
| 107 | bitwise_flag_normalization_mismatch | `tests/unit/test_c_rules_batch2.py` |
| 108 | quic_invisible_frame_limit | same |
| 109 | quic_handshake_eviction_missing | same |
| 110 | bank_lifecycle_refcount_concurrency | `tests/unit/test_c_rules_batch3.py` |
| 111 | io_uring_submission_race_funk | `tests/unit/test_c_rules_batch4.py` |
| 112 | alt_resolution_window_mismatch | `tests/unit/test_c_rules_batch3.py` |
| 113 | keyswitch_atomicity_violation | `tests/unit/test_c_rules_batch4.py` |
| 114 | bls_aggregate_rogue_key_check | `tests/unit/test_c_rules_batch3.py` |
| 115 | unsupported_program_id_divergence | `tests/unit/test_c_rules_batch4.py` |
| 116 | signed_integer_overflow_consensus | `tests/unit/test_c_rules_batch5.py` |
| 117 | unspecified_evaluation_order_side_effects | same |
| 118 | protocol_struct_padding_mismatch | same |
| 119 | division_rounding_divergence | same |
| 120 | unaligned_memory_access_ebpf | same |

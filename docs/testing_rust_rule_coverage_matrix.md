# Rust / Soroban rule coverage matrix



| Task id | Registry slug | Primary automated check |

| ------- | ------------- | ----------------------- |

| 201 | missing_auth_check | `tests/unit/test_rust_stellar_rules.py` |

| 202 | unbounded_instance_storage_growth | `tests/unit/test_rust_stellar_rules.py` |

| 203 | unhandled_cross_contract_failure | `tests/unit/test_rust_stellar_rules.py` |

| 204 | dangerous_raw_val_conversion | `tests/unit/test_rust_stellar_rules.py` |

| 205 | missing_ttl_extension | heuristic (fixture tuning) |

| 206 | improper_error_signaling | heuristic (fixture tuning) |

| 207 | resource_limit_exhaustion_loop | heuristic (fixture tuning) |

| 208 | constructor_reinitialization_risk | heuristic (fixture tuning) |

| 209 | undocumented_unsafe_block | add targeted fixture (manual) |

| 210 | static_mut_ref_access | add targeted fixture (manual) |

| 211 | interior_mutability_sync_violation | add targeted fixture (manual) |

| 212 | unprotected_panic_in_public_api | overlaps `SorobanViolations.rs` `assert!` |

| 213 | redundant_arc_clone_in_loop | add targeted fixture (manual) |

| 214 | missing_async_fn_trait_bound | rare pattern; optional fixture |

| 215 | temporary_lifetime_extension_confusion | rare pattern; optional fixture |

| 216 | forbidden_std_usage | add `use std::...` under `no_std` snippet to test |

| 217 | non_deterministic_state_root | heuristic (Base Azul / state deriv; optional fixture) |

| 218 | async_boundary_panic_leak | heuristic (spawn + unwrap/panic proximity; optional fixture) |

| 219 | serde_binary_codec_mismatch | heuristic (`serde(flatten)` + Serialize/Deserialize; optional fixture) |

| 220 | divergent_fork_choice_assumptions | heuristic (`fork_choice` tokens; optional fixture) |

| 221 | gas_limit_cl_el_mismatch | heuristic (`gas_limit` + batch/batcher; optional fixture) |

| 222 | unbounded_proposal_range | heuristic (proposal + u64 span without guards; optional fixture) |

| 223 | tee_side_channel_via_panic | heuristic (`panic_with_error!` + `panic!`; optional fixture) |



Drift gate manifest: `tests/fixtures/rust_task_coverage.json` (`tests/unit/test_rust_task_coverage_declared.py`, tasks **201-223**).  

Human catalog: `docs/rust_stellar/soroban_rules_catalog.json` + `docs/rust/language_rules_catalog.json` (language catalog includes Base Azul blocks **217-223** plus `review_scenarios` / `review_checklist`).  

HTTP shape: `tests/integration/test_http_rust_fixture_contract.py`.  

Fixture corpus: `tests/fixtures/rust/SorobanViolations.rs`.


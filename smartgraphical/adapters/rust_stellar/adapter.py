"""Soroban (Rust/Stellar) adapter: heuristic extraction into NormalizedAuditModel.

Targets single-crate Soroban contract sources. Uses lexer-light parsing (regex +
brace balancing) analogous to Phase-7 `c_base`, not rustc.

Limitations:
- Complex macros expansion is not modeled; signatures are textual.
- Dataflow is intra-statement heuristic only.

Rule tasks include 201-208 (Soroban, docs/rust_stellar/soroban_rules_catalog.json) and
209-223 (Rust language + Base Azul heuristics, docs/rust/language_rules_catalog.json).
"""
from __future__ import annotations

import os
import re
from typing import Iterator, List

from smartgraphical.core.engine import RuleSpec
from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedFunction,
    NormalizedStateEntity,
    NormalizedType,
)
from smartgraphical.core.rules.rust.language_rules import (
    run_async_boundary_panic_leak,
    run_divergent_fork_choice_assumptions,
    run_forbidden_std_usage,
    run_gas_limit_cl_el_mismatch,
    run_interior_mutability_sync_violation,
    run_missing_async_fn_trait_bound,
    run_non_deterministic_state_root,
    run_redundant_arc_clone_in_loop,
    run_serde_binary_codec_mismatch,
    run_static_mut_ref_access,
    run_temporary_lifetime_extension_confusion,
    run_tee_side_channel_via_panic,
    run_undocumented_unsafe_block,
    run_unbounded_proposal_range,
    run_unprotected_panic_in_public_api,
)
from smartgraphical.core.rules.rust_stellar.rules import (
    run_constructor_reinitialization_risk,
    run_dangerous_raw_val_conversion,
    run_improper_error_signaling,
    run_missing_auth_check,
    run_missing_ttl_extension,
    run_resource_limit_exhaustion_loop,
    run_unbounded_instance_storage_growth,
    run_unhandled_cross_contract_failure,
)

# ---------------------------------------------------------------------------
# Comment stripping (preserve newline count for naive line heuristic)
# ---------------------------------------------------------------------------

_RUST_LINE_COMMENT = re.compile(r'//[^\n]*')
_RUST_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)


def _strip_rust_comments(source: str) -> str:
    source = _RUST_BLOCK_COMMENT.sub(lambda m: '\n' * m.group(0).count('\n'), source)
    return _RUST_LINE_COMMENT.sub(lambda m: ' ' * len(m.group(0)), source)


# ---------------------------------------------------------------------------
# Brace matching
# ---------------------------------------------------------------------------

def _extract_body(cleaned: str, open_brace_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_brace_idx
    while i < len(cleaned):
        c = cleaned[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return cleaned[open_brace_idx + 1 : i], i + 1
        i += 1
    return cleaned[open_brace_idx + 1 :], len(cleaned)


_INVOKE_PLAIN = re.compile(r'(?<!try_)invoke_contract\s*\(')


def _iter_pub_functions_unicode(cleaned: str) -> Iterator[dict]:
    for m in re.finditer(r'\bpub(?:\([^)]*\))?\s+fn\s+(\w+)\s*\(', cleaned):
        name = m.group(1)
        paren_rel = cleaned[m.start() :].find('(')
        if paren_rel < 0:
            continue
        i = m.start() + paren_rel
        depth = 0
        j = i
        while j < len(cleaned):
            ch = cleaned[j]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    params_str = cleaned[i + 1 : j].strip()
                    k = j + 1
                    while k < len(cleaned) and cleaned[k] in ' \t\r\n':
                        k += 1
                    brace_pos = cleaned.find('{', k)
                    if brace_pos < 0:
                        break
                    body, _ = _extract_body(cleaned, brace_pos)
                    visibility = _infer_visibility_pub(cleaned, m.start())
                    yield {'name': name, 'params': params_str, 'body': body, 'visibility': visibility}
                    break
            j += 1


def _infer_visibility_pub(cleaned: str, fn_keyword_pos: int) -> str:
    window = cleaned[max(0, fn_keyword_pos - 40) : fn_keyword_pos + 6]
    if 'pub(crate)' in window.replace(' ', ''):
        return 'crate'
    if re.search(r'\bpub\b', window):
        return 'external'
    return 'internal'


def source_has_contractimpl(source: str) -> bool:
    return bool(re.search(r'#\s*\[\s*contractimpl\b', source))



def rust_split_statements(body: str) -> List[str]:
    """Very coarse splits for rule pattern matching."""
    stmts = []
    for chunk in body.split(';'):
        part = ' '.join(chunk.split())
        if len(part) > 2:
            stmts.append(part + ';')
    return stmts if stmts else ([' '.join(body.split())[:4000]] if body.strip() else [])


def collect_function_facts(fn: NormalizedFunction) -> dict:
    body_l = fn.body.lower()
    stmts_join = ';'.join(fn.exploration_statements).lower()
    unified = stmts_join

    writes_instance = bool(
        re.search(r'\.instance\s*\([^)]*\)\s*\.(?:set|replace|append|extend_ttl)', unified)
        or '.instance()' in unified and '.set(' in unified
    )
    writes_persistent = bool(
        '.persistent()' in unified and '.set(' in unified
    )
    writes_temporary = bool(
        '.temporary()' in unified and '.set(' in unified
    )
    reads_any_storage = 'env.storage()' in unified or '.storage()' in unified
    spaced = unified.replace(' ', '')
    loops = ('for ' in unified or '.iter()' in unified or ' while ' in unified)
    reads_in_loop = loops and reads_any_storage and ('.get(' in unified or '.has(' in unified)
    panic_with_error_pat = bool(re.search(r'panic_with_error\s*!\s*\(', unified.replace(' ', '')))

    return {
        'visibility': fn.visibility or '',
        'is_entrypoint_hint': getattr(fn, 'is_entrypoint', False),
        'calls_require_auth': bool(
            re.search(r'\.require_auth\s*\(|require_auth_for_args\s*\(', unified)
        ),
        'calls_extend_ttl': 'extend_ttl' in unified or 'extend_ttl' in body_l,
        'writes_instance': writes_instance,
        'writes_persistent': writes_persistent,
        'writes_temporary': writes_temporary,
        'mutates_ledger_like': writes_instance or writes_persistent or writes_temporary,
        'reads_any_storage': reads_any_storage,
        'invoke_contract_plain': bool(_INVOKE_PLAIN.search(unified.replace(' ', ''))),
        'try_invoke_contract': 'try_invoke_contract' in spaced,
        'panic_bare': bool(re.search(r'\bpanic\s*!\s*\(', unified)),
        'panic_assert': bool(re.search(r'\b(assert|debug_assert)\s*!\s*\(', unified)),
        'panic_with_error': panic_with_error_pat,
        'reads_storage_in_loop': reads_in_loop,
        'invoke_or_try': bool(_INVOKE_PLAIN.search(spaced)) or 'try_invoke_contract' in spaced,
        '__constructor_like': fn.name.startswith('__constructor'),
        'params_have_vec_map': _params_have_collection(fn.full_source.split('{')[0]),
        'nested_complex_arg': False,
        'within_contractimpl': True,
        'collections_in_params': '',
    }


def _params_have_collection(signature_prefix: str) -> bool:
    return bool(re.search(r'\bVec\s*<|\bMap\s*<', signature_prefix))


def _build_call_edges(
    type_name: str,
    functions: List[NormalizedFunction],
    facts_per_fn: dict[str, dict],
) -> List[NormalizedCallEdge]:
    edges: List[NormalizedCallEdge] = []
    for fn in functions:
        fn_name = fn.name
        fk = facts_per_fn.get(fn_name, {})
        if fk.get('writes_instance'):
            edges.append(
                NormalizedCallEdge(
                    type_name,
                    fn_name,
                    type_name,
                    'LedgerInstancePartition',
                    'function_to_object',
                    label='storage_instance_write',
                )
            )
        if fk.get('writes_persistent'):
            edges.append(
                NormalizedCallEdge(
                    type_name,
                    fn_name,
                    type_name,
                    'LedgerPersistentPartition',
                    'function_to_object',
                    label='storage_persistent_write',
                )
            )
        if fk.get('writes_temporary'):
            edges.append(
                NormalizedCallEdge(
                    type_name,
                    fn_name,
                    type_name,
                    'LedgerTemporaryPartition',
                    'function_to_object',
                    label='storage_temporary_write',
                )
            )
        if fk.get('invoke_contract_plain') or fk.get('try_invoke_contract'):
            edges.append(
                NormalizedCallEdge(
                    type_name,
                    fn_name,
                    type_name,
                    'external_invoke_target',
                    'function_to_object',
                    label='invoke_contract' if fk.get('invoke_contract_plain') else 'try_invoke_contract',
                )
            )
        if 'events()' in ''.join(fn.exploration_statements).replace(' ', ''):
            if '.publish(' in ''.join(fn.exploration_statements).lower():
                edges.append(
                    NormalizedCallEdge(
                        type_name,
                        fn_name,
                        type_name,
                        'SorobanEventPublish',
                        'function_to_event',
                        label='events_publish',
                    )
                )
        if fk.get('calls_require_auth'):
            edges.append(
                NormalizedCallEdge(
                    type_name,
                    'AuthLedgerCheck',
                    type_name,
                    fn_name,
                    'state_to_function',
                    label='require_auth_fact',
                    callsite='auth_dep',
                )
            )
    return edges


def _augment_facts_for_edges(facts: dict) -> dict:
    out = dict(facts)
    cache = ''.join(out.get('_body_join_cache', []) or []).lower()
    out['reads_storage_flat'] = '.get(' in cache or '.has(' in cache
    return out


def build_normalized_model(source_path: str, source_text: str) -> NormalizedAuditModel:
    raw = source_text
    stripped = _strip_rust_comments(raw)
    in_impl = source_has_contractimpl(raw)

    artifact = NormalizedArtifact(
        path=source_path,
        language='rust',
        adapter_name='RustStellarAdapterV0',
    )
    model = NormalizedAuditModel(artifact=artifact)
    stem = os.path.splitext(os.path.basename(source_path))[0]
    type_entry = NormalizedType(name=stem or 'crate', kind='soroban_contract')
    synthetic_states = (
        NormalizedStateEntity(name='LedgerInstancePartition', owner=stem, kind='ledger_instance'),
        NormalizedStateEntity(name='LedgerPersistentPartition', owner=stem, kind='ledger_persistent'),
        NormalizedStateEntity(name='LedgerTemporaryPartition', owner=stem, kind='ledger_temporary'),
        NormalizedStateEntity(name='AuthLedgerCheck', owner=stem, kind='phantom_auth'),
        NormalizedStateEntity(name='SorobanEventPublish', owner=stem, kind='event_sink'),
        NormalizedStateEntity(name='external_invoke_target', owner=stem, kind='cross_contract_placeholder'),
    )
    for entity in synthetic_states:
        type_entry.state_entities.append(entity)

    facts_map: dict[str, dict] = {}

    cleaned = stripped
    for fn_info in _iter_pub_functions_unicode(cleaned):
        visibility = fn_info['visibility']
        stmts = rust_split_statements(fn_info['body'])
        fname = fn_info['name']
        pref = f"pub fn {fname}({fn_info['params']})"
        function = NormalizedFunction(
            name=fname,
            owner=stem,
            inputs=[fn_info['params'].strip()] if fn_info['params'].strip() else [],
            body=fn_info['body'],
            full_source=pref + '{' + fn_info['body'] + '}',
            visibility=visibility,
            is_entrypoint=in_impl and visibility in ('external', 'crate'),
            exploration_statements=stmts if stmts else [' '.join(fn_info['body'].split())[:2000]],
        )
        fk = collect_function_facts(function)
        fk['_body_join_cache'] = function.exploration_statements
        fk = _augment_facts_for_edges(fk)
        facts_map[fname] = fk
        if not in_impl:
            function.is_entrypoint = False

        fk['within_contractimpl'] = in_impl
        type_entry.functions.append(function)
        fk_key = f'{stem}.{fname}'
        model.exploration_data.function_notes[fk_key] = {
            'statement_count': len(function.exploration_statements),
            'raw_statements': function.exploration_statements,
        }
        model.findings_data.function_facts[fk_key] = fk

    model.types.append(type_entry)
    edges = _build_call_edges(stem, type_entry.functions, facts_map)

    inner_call = re.compile(r'\b(?!(?:pub|fn|let|match|self|unsafe)\b)(\w+)\s*\(', re.MULTILINE)
    name_set = {f.name for f in type_entry.functions}

    added_fn_edges: List[NormalizedCallEdge] = []
    for fn in type_entry.functions:
        for sub in inner_call.findall(fn.body):
            if sub in name_set and sub != fn.name:
                added_fn_edges.append(
                    NormalizedCallEdge(
                        stem,
                        fn.name,
                        stem,
                        sub,
                        'function_to_function',
                        label='intracontract_call',
                    )
                )
    model.call_edges = edges + added_fn_edges
    model.rule_groups.setdefault('RustAll', []).extend([
        str(i) for i in range(201, 217)
    ])
    return model


def build_rust_rule_registry() -> dict[str, RuleSpec]:
    return {
        '201': RuleSpec(
            '201',
            201,
            'missing_auth_check',
            'Missing Authorization on Public Entry That Mutates State',
            'authorization',
            'rust_stellar',
            'medium',
            'Require Authorization on mutating ledger paths reachable as contract entrypoints.',
            run_missing_auth_check,
        ),
        '202': RuleSpec(
            '202',
            202,
            'unbounded_instance_storage_growth',
            'Potentially Unbounded Structures in Instance Storage',
            'economic_dos',
            'rust_stellar',
            'medium',
            'Cap serialized instance payloads; shard large aggregates into Persistent keys.',
            run_unbounded_instance_storage_growth,
        ),
        '203': RuleSpec(
            '203',
            203,
            'unhandled_cross_contract_failure',
            'Fallible External Call Without Controlled Error Boundary',
            'cross_contract',
            'rust_stellar',
            'medium',
            'Prefer try_invoke_contract-style APIs and propagate contract errors deliberately.',
            run_unhandled_cross_contract_failure,
        ),
        '204': RuleSpec(
            '204',
            204,
            'dangerous_raw_val_conversion',
            'Complex Collection Inputs Without Explicit Checks',
            'input_validation',
            'rust_stellar',
            'low',
            'Wrap batch arguments in contract-type schemas and enforce max lengths.',
            run_dangerous_raw_val_conversion,
        ),
        '205': RuleSpec(
            '205',
            205,
            'missing_ttl_extension',
            'Ledger Writes Missing TTL Extension Nearby',
            'storage_ttl',
            'rust_stellar',
            'low',
            'Pair persistent/instance writes with extend_ttl or justified off-chain renewal.',
            run_missing_ttl_extension,
        ),
        '206': RuleSpec(
            '206',
            206,
            'improper_error_signaling',
            'Bare panic! Instead of Structured Contract Errors',
            'fuzzing_quality',
            'rust_stellar',
            'high',
            'Prefer panic_with_error! plus ContractError for observable abort reasons.',
            run_improper_error_signaling,
        ),
        '207': RuleSpec(
            '207',
            207,
            'resource_limit_exhaustion_loop',
            'Loops Over Storage That May Exhaust IO Budget',
            'economic_dos',
            'rust_stellar',
            'medium',
            'Batch/paginate ledger reads outside tight loops.',
            run_resource_limit_exhaustion_loop,
        ),
        '208': RuleSpec(
            '208',
            208,
            'constructor_reinitialization_risk',
            'Constructor-Like Entry Missing Reinitialization Guards',
            'upgrade_migration',
            'rust_stellar',
            'low',
            'Guard __constructor with immutably-set admin markers after first initialization.',
            run_constructor_reinitialization_risk,
        ),
        '209': RuleSpec(
            '209',
            209,
            'undocumented_unsafe_block',
            'Unsafe Block or Attribute Without SAFETY Commentary',
            'memory_safety',
            'rust',
            'medium',
            'Document every unsafe block with preceding `// SAFETY:` rationale.',
            run_undocumented_unsafe_block,
        ),
        '210': RuleSpec(
            '210',
            210,
            'static_mut_ref_access',
            'Borrow of static mut Variable',
            'memory_safety',
            'rust',
            'high',
            'Replace raw static mut aliases with concurrency-safe primitives.',
            run_static_mut_ref_access,
        ),
        '211': RuleSpec(
            '211',
            211,
            'interior_mutability_sync_violation',
            'Interior Mutability Proximate to Concurrent Spawns',
            'concurrency',
            'rust',
            'medium',
            'Audit Send/Sync when RefCell-like types appear near spawning APIs.',
            run_interior_mutability_sync_violation,
        ),
        '212': RuleSpec(
            '212',
            212,
            'unprotected_panic_in_public_api',
            'panic!, unwrap(), or expect() on Public Callable',
            'robustness',
            'rust',
            'medium',
            'Return Result instead of trapping in public crates.',
            run_unprotected_panic_in_public_api,
        ),
        '213': RuleSpec(
            '213',
            213,
            'redundant_arc_clone_in_loop',
            'Potential Arc/Rc Clone After Loop Heads',
            'performance',
            'rust',
            'low',
            'Avoid redundant smart-pointer clones inside hot loops.',
            run_redundant_arc_clone_in_loop,
        ),
        '214': RuleSpec(
            '214',
            214,
            'missing_async_fn_trait_bound',
            'Async Closure Pattern Review (AsyncFn* Migration)',
            'maintainability',
            'rust',
            'medium',
            'Prefer AsyncFn/AsyncFnMut/AsyncFnOnce on sufficiently new toolchains.',
            run_missing_async_fn_trait_bound,
        ),
        '215': RuleSpec(
            '215',
            215,
            'temporary_lifetime_extension_confusion',
            'Suspected Borrow Across Temporary Expressions',
            'lifetime',
            'rust',
            'low',
            'Hoist temporaries so borrows clearly outlive their referents.',
            run_temporary_lifetime_extension_confusion,
        ),
        '216': RuleSpec(
            '216',
            216,
            'forbidden_std_usage',
            'std Paths While Crate Banner Is no_std',
            'determinism',
            'rust',
            'high',
            'Route std-only helpers through conditional compilation or rely on core/alloc.',
            run_forbidden_std_usage,
        ),
        '217': RuleSpec(
            '217',
            217,
            'non_deterministic_state_root',
            'Non-deterministic Collections Near State Derivation',
            'determinism',
            'rust',
            'low',
            'Prefer deterministic maps or sorted keys around Merkle/state hashing.',
            run_non_deterministic_state_root,
        ),
        '218': RuleSpec(
            '218',
            218,
            'async_boundary_panic_leak',
            'Panic/unwrap Near Async Spawn Boundary',
            'concurrency',
            'rust',
            'low',
            'Avoid unwrap/panic inside spawned tasks without teardown guarantees.',
            run_async_boundary_panic_leak,
        ),
        '219': RuleSpec(
            '219',
            219,
            'serde_binary_codec_mismatch',
            'serde(flatten) With Serialize/Deserialize Present',
            'serialization',
            'rust',
            'low',
            'Align serde layouts across CL/EL commitment codecs.',
            run_serde_binary_codec_mismatch,
        ),
        '220': RuleSpec(
            '220',
            220,
            'divergent_fork_choice_assumptions',
            'Fork-choice Logic Present',
            'consensus',
            'rust',
            'low',
            'Verify paired EL/CL fork-choice constants remain synchronized.',
            run_divergent_fork_choice_assumptions,
        ),
        '221': RuleSpec(
            '221',
            221,
            'gas_limit_cl_el_mismatch',
            'Gas Limit Near Batching Context',
            'execution',
            'rust',
            'low',
            'Mirror executor gas/env checks inside batching pipelines.',
            run_gas_limit_cl_el_mismatch,
        ),
        '222': RuleSpec(
            '222',
            222,
            'unbounded_proposal_range',
            'Proposal u64 Range Without Obvious Guards',
            'logic',
            'rust',
            'low',
            'Bound proposal spans before expensive replay work.',
            run_unbounded_proposal_range,
        ),
        '223': RuleSpec(
            '223',
            223,
            'tee_side_channel_via_panic',
            'Mixed panic_with_error! and panic! Paths',
            'side_channels',
            'rust',
            'low',
            'Unify signing failure surfaces to reduce timing inference.',
            run_tee_side_channel_via_panic,
        ),
    }


class RustStellarAdapterV0:
    def parse_source(self, source_path: str):
        with open(source_path, 'r', errors='replace') as handle:
            text = handle.read()
        model = build_normalized_model(source_path, text)
        return AnalysisContext(
            path=source_path,
            language='rust',
            reader=None,
            lines=text.splitlines(),
            unified_code=text,
            rets=[],
            hierarchy={},
            high_connections=[],
            normalized_model=model,
        )

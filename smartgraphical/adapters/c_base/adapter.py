"""C base adapter (Phase 7 PoC).

Extracts function-like units from C source files and populates the same
NormalizedAuditModel used by the Solidity pipeline. This allows the shared
rule engine and graph builder to work on C code without changes.

Limitations (acceptable for Phase 7 PoC):
- Function extraction is regex-based; preprocessor macros and GCC nested
  functions may be missed or misidentified.
- No type inference: guards, mutations, and external calls are not
  semantically resolved; exploration_statements carries raw C statements.
- A new C-specific rule module (core/rules/c_node/) pattern-matches on
  exploration_statements, similar to how Solidity normalized rules work.
"""
import os
import re
from copy import deepcopy

from smartgraphical.core.engine import RuleSpec
from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)

from smartgraphical.core.rules.c_node.non_saturating_float_cast import (
    run as run_non_saturating_float_cast,
)
from smartgraphical.core.rules.c_node.unsafe_shift_external_exponent import (
    run as run_unsafe_shift,
)
from smartgraphical.core.rules.c_node.unchecked_return_sensitive import (
    run as run_unchecked_return,
)
from smartgraphical.core.rules.c_node.shared_mem_uaf_pool import (
    run as run_uaf_pool,
)
from smartgraphical.core.rules.c_node.incomplete_reserved_account_list import (
    run as run_reserved_accounts,
)
from smartgraphical.core.rules.c_node.sysvar_decode_callback_type_mismatch import (
    run as run_sysvar_mismatch,
)
from smartgraphical.core.rules.c_node.bitwise_flag_normalization_mismatch import (
    run as run_bitwise_flag,
)
from smartgraphical.core.rules.c_node.quic_invisible_frame_limit import (
    run as run_quic_frame_limit,
)
from smartgraphical.core.rules.c_node.quic_handshake_eviction_missing import (
    run as run_quic_hs_eviction,
)
from smartgraphical.core.rules.c_node.bank_lifecycle_refcount_concurrency import (
    run as run_bank_refcount,
)
from smartgraphical.core.rules.c_node.alt_resolution_window_mismatch import (
    run as run_alt_window,
)
from smartgraphical.core.rules.c_node.bls_aggregate_rogue_key_check import (
    run as run_bls_rogue,
)

# ---------------------------------------------------------------------------
# Source cleaning
# ---------------------------------------------------------------------------

_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_LINE_COMMENT = re.compile(r'//[^\n]*')

# Keywords that should never be captured as function names.
_SKIP_KEYWORDS = frozenset({
    'if', 'for', 'while', 'switch', 'do', 'else', 'return',
    'typedef', 'struct', 'enum', 'union', 'sizeof', 'alignof',
    'offsetof', 'assert', 'FD_TEST', 'FD_LIKELY', 'FD_UNLIKELY',
    'defined', 'extern',
})

# Pattern: one or more return-type tokens, then function name, then (params) {
# Uses re.DOTALL so whitespace tokens match newlines (multi-line signatures).
_FUNC_OPEN = re.compile(
    r'[\w\*]+(?:\s+[\w\*]+)*\s+'   # return type (one or more tokens)
    r'(\w+)\s*'                     # function name  (group 1)
    r'\([^;{]*?\)\s*'              # params — no ; or { inside
    r'(?:FD_FN_\w+\s*)*'           # optional trailing Firedancer macros
    r'\{',                          # opening brace of body
    re.DOTALL,
)


def _clean(source):
    """Strip comments while preserving line counts (replace with spaces)."""
    source = _BLOCK_COMMENT.sub(lambda m: ' ' * len(m.group(0)), source)
    source = _LINE_COMMENT.sub(lambda m: ' ' * len(m.group(0)), source)
    return source


def _extract_body(cleaned, open_brace_idx):
    """Return (body_text, end_idx) for the block starting at open_brace_idx."""
    depth = 0
    i = open_brace_idx
    while i < len(cleaned):
        c = cleaned[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return cleaned[open_brace_idx + 1:i], i + 1
        i += 1
    return cleaned[open_brace_idx + 1:], len(cleaned)


def _split_statements(body):
    """Split function body into normalized statement strings."""
    stmts = []
    for part in re.split(r'[;\n]', body):
        part = ' '.join(part.split())
        if len(part) > 2:
            stmts.append(part)
    return stmts


def _parse_inputs(params_str):
    """Convert a raw C parameter string to a list of token lists."""
    inputs = []
    if not params_str.strip() or params_str.strip() in ('void', '...'):
        return inputs
    for param in params_str.split(','):
        parts = param.strip().split()
        if parts:
            inputs.append(parts)
    return inputs


def extract_c_functions(source_text):
    """
    Yield dicts with keys: name, params_str, body, visibility.

    Visibility is 'internal' when the function carries a 'static' qualifier,
    'external' otherwise (C external linkage).
    """
    cleaned = _clean(source_text)
    seen_open_braces = set()

    for match in _FUNC_OPEN.finditer(cleaned):
        func_name = match.group(1)
        if func_name in _SKIP_KEYWORDS:
            continue

        # The match ends just after '{'; the '{' is at match.end() - 1.
        open_brace_idx = match.end() - 1
        if open_brace_idx in seen_open_braces:
            continue
        seen_open_braces.add(open_brace_idx)

        body, _ = _extract_body(cleaned, open_brace_idx)

        matched_text = match.group(0)
        paren_open = matched_text.index('(')
        paren_close = matched_text.rindex(')')
        params_str = matched_text[paren_open + 1:paren_close]

        # Infer visibility from tokens in the matched signature text.
        tokens = set(matched_text.split())
        visibility = 'internal' if 'static' in tokens else 'external'

        yield {
            'name': func_name,
            'params_str': params_str,
            'body': body,
            'visibility': visibility,
        }


# ---------------------------------------------------------------------------
# Normalized model builder
# ---------------------------------------------------------------------------

def build_normalized_model(source_path, source_text):
    artifact = NormalizedArtifact(
        path=source_path,
        language='c',
        adapter_name='CBaseAdapterV0',
    )
    model = NormalizedAuditModel(artifact=artifact)

    # Use the filename stem as the translation-unit type name.
    unit_name = os.path.splitext(os.path.basename(source_path))[0]
    type_entry = NormalizedType(name=unit_name, kind='translation_unit')

    for func_info in extract_c_functions(source_text):
        stmts = _split_statements(func_info['body'])
        inputs = _parse_inputs(func_info['params_str'])
        visibility = func_info['visibility']

        function = NormalizedFunction(
            name=func_info['name'],
            owner=unit_name,
            inputs=inputs,
            body=func_info['body'],
            visibility=visibility,
            is_entrypoint=(visibility == 'external'),
            exploration_statements=stmts,
        )
        type_entry.functions.append(function)

        function_key = f"{unit_name}.{func_info['name']}"
        model.exploration_data.function_notes[function_key] = {
            'statement_count': len(stmts),
            'raw_statements': stmts,
        }
        model.findings_data.function_facts[function_key] = {
            'visibility': visibility,
            'entrypoint': visibility == 'external',
            'statement_count': len(stmts),
        }

    model.types.append(type_entry)
    return model


# ---------------------------------------------------------------------------
# Rule registry for C / Solana node PoC
# Task IDs start at 101 to avoid collision with Solidity registry (1-11).
# ---------------------------------------------------------------------------

def build_c_rule_registry():
    return {
        '101': RuleSpec(
            '101', 101, 'non_saturating_float_cast',
            'Rust-Incompatible Floating Point Cast',
            'consensus_failure', 'c_specific', 'high',
            'Use fd_rust_cast_double_to_ulong or equivalent saturating helper aligned with Rust behavior.',
            run_non_saturating_float_cast,
        ),
        '102': RuleSpec(
            '102', 102, 'unsafe_shift_external_exponent',
            'Undefined Behavior in Shift Operations from External Input',
            'denial_of_service', 'c_specific', 'high',
            'Validate shift exponent is strictly less than 64 before the shift.',
            run_unsafe_shift,
        ),
        '103': RuleSpec(
            '103', 103, 'unchecked_return_sensitive',
            'Unchecked Return Value in Security Critical Calls',
            'improper_error_handling', 'portable_with_adapter', 'high',
            'Always check return codes from security-critical APIs using FD_TEST or conditional checks.',
            run_unchecked_return,
        ),
        '104': RuleSpec(
            '104', 104, 'shared_mem_uaf_pool',
            'Use-After-Free in Shared Memory Pools',
            'memory_safety', 'c_specific', 'medium',
            'Nullify the pointer immediately after release and validate ownership before further access.',
            run_uaf_pool,
        ),
        '105': RuleSpec(
            '105', 105, 'incomplete_reserved_account_list',
            'Missing Reserved Account in Unwritable List',
            'consensus_failure', 'node_specific', 'medium',
            'Synchronize the local unwritable account list with the pinned Agave reserved_account_keys registry.',
            run_reserved_accounts,
        ),
        '106': RuleSpec(
            '106', 106, 'sysvar_decode_callback_type_mismatch',
            'Function Type Mismatch in Sysvar Decode Callbacks',
            'control_flow_integrity', 'node_specific', 'high',
            'Ensure decode callback signature exactly matches the typedef in fd_sysvar_cache.h.',
            run_sysvar_mismatch,
        ),
        '107': RuleSpec(
            '107', 107, 'bitwise_flag_normalization_mismatch',
            'Bitwise AND for Flag Normalization in Consensus Hashes',
            'consensus_failure', 'portable_with_adapter', 'high',
            'Replace field & 1 with !!field or (bool) cast to match Agave boolean normalization.',
            run_bitwise_flag,
        ),
        '108': RuleSpec(
            '108', 108, 'quic_invisible_frame_limit',
            'Missing Limit on Invisible QUIC Protocol Frames',
            'denial_of_service', 'node_specific', 'high',
            'Implement a per-packet frame counter cap, for example frame_count < MAX_FRAMES.',
            run_quic_frame_limit,
        ),
        '109': RuleSpec(
            '109', 109, 'quic_handshake_eviction_missing',
            'Missing Handshake Eviction Strategy',
            'denial_of_service', 'node_specific', 'high',
            'Implement LIFO or oldest-incomplete eviction for the handshake pool before rejecting new connections.',
            run_quic_hs_eviction,
        ),
        '110': RuleSpec(
            '110', 110, 'bank_lifecycle_refcount_concurrency',
            'Unsafe Bank Reference Counting in Shared Memory',
            'memory_safety', 'c_specific', 'medium',
            'Use __atomic_fetch_add or fd_bank_ref_inc for refcount operations in shared workspaces.',
            run_bank_refcount,
        ),
        '112': RuleSpec(
            '112', 112, 'alt_resolution_window_mismatch',
            'Incorrect ALT Resolution Slot Window',
            'correctness', 'node_specific', 'high',
            'Use exactly 512 as the slot lookback window in ALT resolution to match Agave semantics.',
            run_alt_window,
        ),
        '114': RuleSpec(
            '114', 114, 'bls_aggregate_rogue_key_check',
            'Missing Rogue Key Protection in Alpenglow Aggregation',
            'cryptographic_safety', 'node_specific', 'low',
            'Implement proof-of-possession checks for all validator public keys before aggregation.',
            run_bls_rogue,
        ),
    }


# ---------------------------------------------------------------------------
# Adapter class
# ---------------------------------------------------------------------------

class CBaseAdapterV0:
    def parse_source(self, source_path):
        with open(source_path, 'r', errors='replace') as f:
            source_text = f.read()

        model = build_normalized_model(source_path, source_text)
        return AnalysisContext(
            path=source_path,
            language='c',
            reader=None,
            lines=source_text.splitlines(),
            unified_code=source_text,
            rets=[],
            hierarchy={},
            high_connections=[],
            normalized_model=model,
        )

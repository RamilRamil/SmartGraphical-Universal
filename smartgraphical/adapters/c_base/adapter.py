"""C base adapter (Phase 7 PoC).

Extracts function-like units from C source files and populates the same
NormalizedAuditModel used by the Solidity pipeline. This allows the shared
rule engine and graph builder to work on C code without changes.

Graph-oriented additions (still heuristic):
- Per-TU call edges: regex `name(` tokens in each function body, emitted as
  function_to_function (including callees outside the TU as external nodes).
- Struct nodes: `struct Name {` tags become NormalizedStateEntity entries.
- Typedef-of-struct aliases: `typedef struct ... } Alias;` -> `kind=typedef_struct`
  (Phase B); `struct_names` for edges includes both struct tags and those aliases.
- Tightened `T*` heuristic: skip primitive-like typenames (Phase B).
- Optional `struct_field_access_hints` in `findings_data.function_facts` when a
  parameter binds to a known struct/typedef and body uses `param->field`.
- Included .c templates: #include with double-quoted or angle-bracket path
  ending in .c -> workspace node (kind include_template). **One** heuristic edge
  per inc node from a TU anchor (Phase A1b; kind `function_to_include_template`,
  source sentinel `__tu_include_anchor__`). Basename collision policy:
  first path -> inc:<basename>; further distinct paths with same basename ->
  inc:<basename>~<8-hex(path)>.
- Struct use edges function -> struct when signature/body mentions struct T
  or T* (function_to_workspace).

Limitations (acceptable for Phase 7 PoC):
- Function extraction is regex-based; preprocessor macros and GCC nested
  functions may be missed or misidentified.
- No type inference: guards, mutations, and external calls are not
  semantically resolved; exploration_statements carries raw C statements.
- C rule modules: core/rules/c/{portable_with_adapter,c_specific}/ and
  core/rules/c_node/node_specific/ (scope in docs/c_node_rules_catalog.json).
  They pattern-match on exploration_statements like Solidity normalized rules.
"""
import hashlib
import os
import re

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

from smartgraphical.core.rules.c.c_specific.bank_lifecycle_refcount_concurrency import (
    run as run_bank_refcount,
)
from smartgraphical.core.rules.c.c_specific.io_uring_submission_race_funk import (
    run as run_io_uring_race,
)
from smartgraphical.core.rules.c.c_specific.non_saturating_float_cast import (
    run as run_non_saturating_float_cast,
)
from smartgraphical.core.rules.c.c_specific.shared_mem_uaf_pool import (
    run as run_uaf_pool,
)
from smartgraphical.core.rules.c.c_specific.signed_integer_overflow_consensus import (
    run as run_signed_overflow_consensus,
)
from smartgraphical.core.rules.c.c_specific.unsafe_shift_external_exponent import (
    run as run_unsafe_shift,
)
from smartgraphical.core.rules.c.c_specific.unspecified_evaluation_order_side_effects import (
    run as run_unspecified_eval_order,
)
from smartgraphical.core.rules.c_node.node_specific.alt_resolution_window_mismatch import (
    run as run_alt_window,
)
from smartgraphical.core.rules.c_node.node_specific.bls_aggregate_rogue_key_check import (
    run as run_bls_rogue,
)
from smartgraphical.core.rules.c_node.node_specific.incomplete_reserved_account_list import (
    run as run_reserved_accounts,
)
from smartgraphical.core.rules.c_node.node_specific.keyswitch_atomicity_violation import (
    run as run_keyswitch_atomicity,
)
from smartgraphical.core.rules.c_node.node_specific.protocol_struct_padding_mismatch import (
    run as run_protocol_struct_padding,
)
from smartgraphical.core.rules.c_node.node_specific.quic_handshake_eviction_missing import (
    run as run_quic_hs_eviction,
)
from smartgraphical.core.rules.c_node.node_specific.quic_invisible_frame_limit import (
    run as run_quic_frame_limit,
)
from smartgraphical.core.rules.c_node.node_specific.sysvar_decode_callback_type_mismatch import (
    run as run_sysvar_mismatch,
)
from smartgraphical.core.rules.c_node.node_specific.unaligned_memory_access_ebpf import (
    run as run_unaligned_mem_access,
)
from smartgraphical.core.rules.c.portable_with_adapter.bitwise_flag_normalization_mismatch import (
    run as run_bitwise_flag,
)
from smartgraphical.core.rules.c.portable_with_adapter.division_rounding_divergence import (
    run as run_division_rounding_divergence,
)
from smartgraphical.core.rules.c.portable_with_adapter.unchecked_return_sensitive import (
    run as run_unchecked_return,
)
from smartgraphical.core.rules.c.portable_with_adapter.unsupported_program_id_divergence import (
    run as run_unsupported_program_id,
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

# Tokens before `(` that are not function calls (heuristic call-graph extraction).
_C_CALL_SKIP = frozenset({
    'if', 'for', 'while', 'switch', 'case', 'do', 'else', 'return',
    'sizeof', 'alignof', 'offsetof', 'typeof', '__typeof',
    '_Generic', '_Static_assert', 'static_assert',
    'FD_LIKELY', 'FD_UNLIKELY', 'FD_TEST',
})

_CALL_TOKEN_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
_STRUCT_HEAD_RE = re.compile(r'\bstruct\s+([A-Za-z_]\w*)\s*\{')
_TYPEDEF_STRUCT_KW = re.compile(r'\btypedef\s+struct\b')

# Exclude primitive / libc typedef names from standalone `T*` matching (Phase B).
_C_STAR_TYPENAME_DENY = frozenset({
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned',
    'size_t', 'ssize_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uintptr_t', 'intptr_t',
    'bool', '_bool',
})

_FIELD_DEREF_RE = re.compile(r'\b([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\b')
# Template .c includes: POSIX-ish paths; angle variant for system-style includes.
_INCLUDE_QUOTED_C_RE = re.compile(r'#include\s+"([^"]+\.c)"')
_INCLUDE_ANGLE_C_RE = re.compile(r'#include\s+<([^>]+\.c)>')
# Sentinel source_name for include-template edges: one edge per inc from TU (A1b).
_TU_INCLUDE_EDGE_SOURCE = "__tu_include_anchor__"

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


def _extract_call_name(stmt):
    """Return the first function-like call token from a statement."""
    match = re.search(r'\b([A-Za-z_]\w*)\s*\(', stmt)
    if not match:
        return ''
    return match.group(1)


def _extract_return_error(stmt):
    """Return symbolic error token from `return ERR_*` or empty string."""
    match = re.search(r'\breturn\s+([A-Z_][A-Z0-9_]*)\b', stmt)
    if not match:
        return ''
    return match.group(1)


def _extract_io_uring_submit_site(stmt, idx, all_stmts):
    """Extract io_uring submit call fact from a statement if present."""
    match = re.search(r'\bio_uring_submit\s*\(([^)]*)\)', stmt)
    if not match:
        return None
    call_args = [part.strip() for part in match.group(1).split(',') if part.strip()]
    ring_expr = call_args[0] if call_args else ''
    ring_lower = ring_expr.lower()
    lookback = all_stmts[max(0, idx - 2): idx + 1]
    lock_tokens = ('lock', 'mutex', 'spin', 'guard', 'sync')
    guarded = any(any(token in s.lower() for token in lock_tokens) for s in lookback)
    private_markers = ('private', 'local', 'tile->', 'per_tile')
    shared_markers = ('shared', 'global', 'common')
    return {
        'statement_index': idx,
        'statement': stmt,
        'ring_expr': ring_expr,
        'is_private': any(marker in ring_lower for marker in private_markers),
        'is_shared': any(marker in ring_lower for marker in shared_markers),
        'is_guarded': guarded,
    }


def _extract_dataflow_facts(stmts):
    """Build minimal dataflow facts for C/node rules."""
    facts = {
        'ordered_calls': [],
        'io_uring_submit_sites': [],
        'return_error_codes': [],
        'program_guard_sites': [],
        'tile_markers': [],
    }
    tile_tokens = ('tile', 'exec', 'replay', 'store')
    for idx, stmt in enumerate(stmts):
        stmt_lower = stmt.lower()
        call_name = _extract_call_name(stmt)
        if call_name:
            facts['ordered_calls'].append({
                'statement_index': idx,
                'call': call_name,
            })
        io_submit = _extract_io_uring_submit_site(stmt, idx, stmts)
        if io_submit:
            facts['io_uring_submit_sites'].append(io_submit)
        ret_code = _extract_return_error(stmt)
        if ret_code:
            facts['return_error_codes'].append({
                'statement_index': idx,
                'code': ret_code,
                'statement': stmt,
            })
        if (
            'program' in stmt_lower
            and ('id' in stmt_lower or 'exists' in stmt_lower)
            and ('if' in stmt_lower or 'switch' in stmt_lower)
        ):
            facts['program_guard_sites'].append({
                'statement_index': idx,
                'statement': stmt,
            })
        if any(token in stmt_lower for token in tile_tokens):
            facts['tile_markers'].append({
                'statement_index': idx,
                'statement': stmt,
            })
    return facts


def _function_body_text(function: NormalizedFunction) -> str:
    body = getattr(function, 'body', '') or ''
    if body.strip():
        return body
    stmts = getattr(function, 'exploration_statements', []) or []
    return '\n'.join(stmts)


def _callee_names_from_body(body: str) -> list:
    seen = []
    found = set()
    for m in _CALL_TOKEN_RE.finditer(body):
        name = m.group(1)
        if name in _C_CALL_SKIP:
            continue
        if name not in found:
            found.add(name)
            seen.append(name)
    return seen


def _build_c_call_edges(unit_name: str, functions: list) -> list:
    seen_pairs = set()
    edges = []
    for fn in functions:
        caller = getattr(fn, 'name', '') or ''
        if not caller:
            continue
        body = _function_body_text(fn)
        for callee in _callee_names_from_body(body):
            pair = (caller, callee)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            edges.append(NormalizedCallEdge(
                unit_name,
                caller,
                unit_name,
                callee,
                'function_to_function',
                label='regex_call_heuristic',
            ))
    return edges


def _params_blob_from_inputs(inputs: list) -> str:
    if not inputs:
        return ''
    return ', '.join(' '.join(parts) for parts in inputs if parts)


def _ok_name_for_star_heuristic(name: str) -> bool:
    if not name or len(name) < 2:
        return False
    if name.lower() in _C_STAR_TYPENAME_DENY:
        return False
    return True


def _haystack_refs_struct(hnorm: str, struct_name: str) -> bool:
    if f'struct {struct_name}' in hnorm:
        return True
    if not _ok_name_for_star_heuristic(struct_name):
        return False
    return bool(re.search(rf'\b{re.escape(struct_name)}\s*\*', hnorm))


def _param_struct_bindings_from_inputs(inputs: list, struct_names: set) -> dict:
    """Map parameter name -> struct or typedef_struct tag used in its type (heuristic)."""
    out = {}
    if not inputs or not struct_names:
        return out
    for parts in inputs:
        if not parts:
            continue
        line = ' '.join(parts)
        ident = parts[-1]
        if not re.match(r'^[A-Za-z_]\w*$', ident):
            continue
        for sname in sorted(struct_names):
            if re.search(rf'\bstruct\s+{re.escape(sname)}\b', line):
                out[ident] = sname
                break
            if re.search(rf'\b{re.escape(sname)}\s*\*', line):
                out[ident] = sname
                break
    return out


def _collect_struct_field_access_hints(body: str, bindings: dict) -> list:
    hints = []
    seen = set()
    for m in _FIELD_DEREF_RE.finditer(body):
        ptr, field = m.group(1), m.group(2)
        tag = bindings.get(ptr)
        if not tag:
            continue
        key = (tag, field)
        if key in seen:
            continue
        seen.add(key)
        hints.append({
            'struct': tag,
            'field': field,
            'via': ptr,
        })
    return hints


def _extract_typedef_struct_alias_entities(
    unit_name: str, cleaned_source: str, struct_tag_names: set,
) -> list:
    """typedef struct { ... } Alias; or typedef struct Tag { ... } Alias; -> typedef_struct entities."""
    entities = []
    seen = set()
    for m in _TYPEDEF_STRUCT_KW.finditer(cleaned_source):
        j = m.end()
        while j < len(cleaned_source) and cleaned_source[j] in ' \t\n\v\f\r':
            j += 1
        if j >= len(cleaned_source):
            break
        if cleaned_source[j] == '{':
            open_idx = j
        else:
            tag_open = re.match(r'([A-Za-z_]\w*)\s*\{', cleaned_source[j:])
            if not tag_open:
                continue
            open_idx = j + tag_open.end() - 1
        if open_idx >= len(cleaned_source) or cleaned_source[open_idx] != '{':
            continue
        _inner, after_brace = _extract_body(cleaned_source, open_idx)
        k = after_brace
        while k < len(cleaned_source) and cleaned_source[k] in ' \t\n\v\f\r':
            k += 1
        alias_m = re.match(r'([A-Za-z_]\w*)\s*;', cleaned_source[k:])
        if not alias_m:
            continue
        alias = alias_m.group(1)
        if alias in struct_tag_names or alias in seen:
            continue
        if not _ok_name_for_star_heuristic(alias):
            continue
        seen.add(alias)
        entities.append(NormalizedStateEntity(
            name=alias,
            owner=unit_name,
            kind='typedef_struct',
            raw_signature='typedef struct { ... } %s;' % alias,
        ))
    return sorted(entities, key=lambda e: e.name)


def _build_c_struct_use_edges(
    unit_name: str, functions: list, struct_names: set,
) -> list:
    if not struct_names:
        return []
    seen_pairs = set()
    edges = []
    for fn in functions:
        fname = getattr(fn, 'name', '') or ''
        if not fname:
            continue
        inputs = getattr(fn, 'inputs', []) or []
        hay = _params_blob_from_inputs(inputs) + '\n' + _function_body_text(fn)
        hnorm = ' '.join(hay.split())
        for sname in struct_names:
            if not _haystack_refs_struct(hnorm, sname):
                continue
            pair = (fname, sname)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            edges.append(NormalizedCallEdge(
                unit_name,
                fname,
                unit_name,
                sname,
                'function_to_workspace',
                label='struct_use_heuristic',
            ))
    return edges


def _extract_include_template_entities(unit_name: str, cleaned_source: str) -> list:
    """Workspace nodes for #include '*.c' (quoted or angle brackets).

    Deduplicate exact path. Basename policy: first path wins inc:base; further
    distinct paths sharing basename get inc:base~<sha256[:8]>.
    """
    events = []
    for m in _INCLUDE_QUOTED_C_RE.finditer(cleaned_source):
        raw = m.group(1).strip().replace('\\', '/')
        events.append((m.start(), raw, '"'))
    for m in _INCLUDE_ANGLE_C_RE.finditer(cleaned_source):
        raw = m.group(1).strip().replace('\\', '/')
        events.append((m.start(), raw, '>'))
    events.sort(key=lambda t: t[0])

    seen_paths = set()
    basename_first = {}
    entities = []
    for _pos, raw_path, br in events:
        if not raw_path or raw_path in seen_paths:
            continue
        seen_paths.add(raw_path)
        base = os.path.basename(raw_path)
        if not base:
            continue
        if base not in basename_first:
            basename_first[base] = raw_path
            name = f'inc:{base}'
        elif basename_first[base] == raw_path:
            continue
        else:
            digest = hashlib.sha256(raw_path.encode('utf-8')).hexdigest()[:8]
            name = f'inc:{base}~{digest}'
        if br == '"':
            sig = f'#include "{raw_path}"'
        else:
            sig = f'#include <{raw_path}>'
        entities.append(NormalizedStateEntity(
            name=name,
            owner=unit_name,
            kind='include_template',
            raw_signature=sig,
        ))
    return sorted(entities, key=lambda e: e.name)


def _build_c_include_template_edges(
    unit_name: str, inc_names: list,
) -> list:
    if not inc_names:
        return []
    out = []
    for inc in inc_names:
        out.append(NormalizedCallEdge(
            unit_name,
            _TU_INCLUDE_EDGE_SOURCE,
            unit_name,
            inc,
            'function_to_include_template',
            label='translation_unit_include',
        ))
    return out


def _extract_struct_state_entities(unit_name: str, cleaned_source: str) -> list:
    names = sorted(set(_STRUCT_HEAD_RE.findall(cleaned_source)))
    return [
        NormalizedStateEntity(
            name=n,
            owner=unit_name,
            kind='struct',
            raw_signature=f'struct {n} {{ ... }}',
        )
        for n in names
    ]


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

    cleaned = _clean(source_text)
    struct_entities = _extract_struct_state_entities(unit_name, cleaned)
    struct_tag_names = {e.name for e in struct_entities}
    typedef_entities = _extract_typedef_struct_alias_entities(
        unit_name, cleaned, struct_tag_names,
    )
    include_entities = _extract_include_template_entities(unit_name, cleaned)
    type_entry.state_entities = struct_entities + typedef_entities + include_entities
    struct_names = struct_tag_names | {e.name for e in typedef_entities}

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
        bindings = _param_struct_bindings_from_inputs(inputs, struct_names)
        hints = _collect_struct_field_access_hints(func_info['body'], bindings)
        ffacts = {
            'visibility': visibility,
            'entrypoint': visibility == 'external',
            'statement_count': len(stmts),
            'dataflow': _extract_dataflow_facts(stmts),
        }
        if hints:
            ffacts['struct_field_access_hints'] = hints
        model.findings_data.function_facts[function_key] = ffacts

    call_edges = _build_c_call_edges(unit_name, type_entry.functions)
    call_edges.extend(_build_c_struct_use_edges(
        unit_name, type_entry.functions, struct_names,
    ))
    inc_names = [e.name for e in include_entities]
    call_edges.extend(_build_c_include_template_edges(unit_name, inc_names))
    model.call_edges = call_edges
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
            'C float-to-unsigned cast (Rust parity heuristic)',
            'consensus_failure', 'c_specific', 'medium',
            (
                'If the operand is floating-point, use fd_rust_cast_double_to_ulong '
                'or an equivalent saturating helper for Rust-aligned semantics.'
            ),
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
        '111': RuleSpec(
            '111', 111, 'io_uring_submission_race_funk',
            'Race Condition in Funk Database io_uring Submissions',
            'data_integrity', 'c_specific', 'low',
            'Use per-tile io_uring instances or explicit synchronization around shared ring submission.',
            run_io_uring_race,
        ),
        '112': RuleSpec(
            '112', 112, 'alt_resolution_window_mismatch',
            'Incorrect ALT Resolution Slot Window',
            'correctness', 'node_specific', 'high',
            'Use exactly 512 as the slot lookback window in ALT resolution to match Agave semantics.',
            run_alt_window,
        ),
        '113': RuleSpec(
            '113', 113, 'keyswitch_atomicity_violation',
            'Non-Atomic Identity Switch Coordination',
            'liveness', 'node_specific', 'medium',
            'Enforce HALT -> FLUSH -> UPDATE -> RESUME ordering in keyswitch path.',
            run_keyswitch_atomicity,
        ),
        '114': RuleSpec(
            '114', 114, 'bls_aggregate_rogue_key_check',
            'Missing Rogue Key Protection in Alpenglow Aggregation',
            'cryptographic_safety', 'node_specific', 'low',
            'Implement proof-of-possession checks for all validator public keys before aggregation.',
            run_bls_rogue,
        ),
        '115': RuleSpec(
            '115', 115, 'unsupported_program_id_divergence',
            'Semantic Mismatch on UnsupportedProgramId Error',
            'consensus_failure', 'portable_with_adapter', 'high',
            'Return ERR_UNSUPPORTED_PROGRAM_ID on unknown program paths to match Agave error priority.',
            run_unsupported_program_id,
        ),
        '116': RuleSpec(
            '116', 116, 'signed_integer_overflow_consensus',
            'Unchecked Signed Integer Overflow in Consensus Logic',
            'consensus_failure', 'c_specific', 'high',
            'Use overflow-safe helpers or built-ins and enforce protocol-aligned overflow handling.',
            run_signed_overflow_consensus,
        ),
        '117': RuleSpec(
            '117', 117, 'unspecified_evaluation_order_side_effects',
            'Unspecified Order of Evaluation with Side Effects',
            'correctness', 'c_specific', 'medium',
            'Materialize side-effect calls into locals to enforce deterministic ordering.',
            run_unspecified_eval_order,
        ),
        '118': RuleSpec(
            '118', 118, 'protocol_struct_padding_mismatch',
            'Implicit Padding in Protocol-Mapped Structures',
            'data_integrity', 'node_specific', 'high',
            'Use explicit packed/aligned/static_assert layout guards for protocol structs.',
            run_protocol_struct_padding,
        ),
        '119': RuleSpec(
            '119', 119, 'division_rounding_divergence',
            'Signed Division/Modulo Rounding Mismatch',
            'consensus_failure', 'portable_with_adapter', 'medium',
            'Use explicit division helpers encoding protocol rounding semantics.',
            run_division_rounding_divergence,
        ),
        '120': RuleSpec(
            '120', 120, 'unaligned_memory_access_ebpf',
            'Unaligned Memory Access in Flamenco VM',
            'control_flow_integrity', 'node_specific', 'high',
            'Add explicit alignment checks before VM pointer-cast memory access.',
            run_unaligned_mem_access,
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

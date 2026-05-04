"""Rule C18 (task 118): protocol_struct_padding_mismatch.

Detects protocol-mapped struct declarations that are later cast from raw
network/disk buffers without packed/alignment guard.
"""

from smartgraphical.core.engine import make_findings

_PROTO_BUFFER_TOKENS = ('buffer', 'buf', 'packet', 'wire', 'disk', 'shred', 'account')

_META = dict(
    task_id='118',
    legacy_code=118,
    slug='protocol_struct_padding_mismatch',
    title='Implicit Padding in Protocol-Mapped Structures',
    category='data_integrity',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Use explicit layout control (packed/aligned/static_assert size checks) '
        'for protocol-mapped structs.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            for idx, stmt in enumerate(stmts):
                stmt_lower = stmt.lower()
                if 'struct' not in stmt_lower:
                    continue
                if '{' not in stmt:
                    continue
                if '__attribute__((packed))' in stmt_lower or 'alignas(' in stmt_lower:
                    continue
                window = stmts[idx:min(len(stmts), idx + 4)]
                has_buffer_cast = any(
                    '(struct' in w.lower() and any(token in w.lower() for token in _PROTO_BUFFER_TOKENS)
                    for w in window
                )
                has_layout_assert = any('static_assert' in w.lower() and 'sizeof' in w.lower() for w in window)
                if not has_buffer_cast or has_layout_assert:
                    continue
                alerts.append({
                    'code': 118,
                    'message': (
                        f"Protocol struct without explicit layout guard in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

"""Rule C16 (task 116): signed_integer_overflow_consensus.

Detects signed arithmetic in consensus-sensitive code paths that does not use
overflow-safe helpers or explicit overflow checks.
"""
import re

from smartgraphical.core.engine import make_findings

_SIGNED_TYPE_TOKENS = ('int ', 'long ', 'ssize_t', 'ptrdiff_t')
_ARITHMETIC = re.compile(r'[+\-*]')
_SAFE_TOKENS = (
    '__builtin_add_overflow',
    '__builtin_sub_overflow',
    '__builtin_mul_overflow',
    'fd_uint_add_sat',
    'fd_long_add_sat',
    'fd_long_mul_sat',
    'checked_add',
    'checked_mul',
)
_CONSENSUS_TOKENS = ('runtime', 'rent', 'reward', 'balance', 'lamport', 'stake')

_META = dict(
    task_id='116',
    legacy_code=116,
    slug='signed_integer_overflow_consensus',
    title='Unchecked Signed Integer Overflow in Consensus Logic',
    category='consensus_failure',
    portability='c_specific',
    confidence='high',
    remediation_hint=(
        'Use overflow-safe built-ins or wrappers and handle overflow in a '
        'protocol-consistent way.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                stmt_lower = stmt.lower()
                if not any(token in stmt for token in _SIGNED_TYPE_TOKENS):
                    continue
                if not _ARITHMETIC.search(stmt):
                    continue
                if any(token in stmt for token in _SAFE_TOKENS):
                    continue
                if not any(token in stmt_lower for token in _CONSENSUS_TOKENS):
                    continue
                alerts.append({
                    'code': 116,
                    'message': (
                        f"Signed arithmetic without overflow guard in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

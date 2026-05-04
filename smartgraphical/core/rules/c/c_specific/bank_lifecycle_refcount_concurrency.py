"""Rule C10 (task 110): bank_lifecycle_refcount_concurrency.

Detects non-atomic increments and decrements of bank reference counter
fields in shared-memory regions. In the replay/banks component multiple
tiles access bank structures concurrently; a plain `bank->ref_cnt++` is
a data race that can lead to use-after-free or double-free on bank state.

Heuristic (PoC level):
- Scan statements for field access patterns matching known refcount field
  names (ref_cnt, ref_count, bank_ref, refcnt).
- Flag usages with postfix ++ or -- operators.
- Skip statements that already contain an atomic primitive token
  (__atomic_, __sync_, fd_bank_ref_, CAS, XADD).

Scope: c_specific
Priority: 35
"""
import re

from smartgraphical.core.engine import make_findings

# Known refcount field names used in Firedancer bank structures.
_REFCOUNT_FIELDS = frozenset({
    'ref_cnt', 'ref_count', 'bank_ref', 'refcnt', 'ref',
})

# Matches: ->field++ / ->field-- / .field++ / .field--
_NONATOMIC_OP = re.compile(
    r'(?:->|\.)(\w+)\s*(?:\+\+|--)'
)

# Tokens that indicate an atomic primitive is already in use for this stmt.
_ATOMIC_TOKENS = [
    '__atomic_', '__sync_', 'fd_bank_ref_', 'CAS', 'XADD',
    'atomic_fetch', 'InterlockedIncrement',
]

_META = dict(
    task_id='110',
    legacy_code=110,
    slug='bank_lifecycle_refcount_concurrency',
    title='Unsafe Bank Reference Counting in Shared Memory',
    category='memory_safety',
    portability='c_specific',
    confidence='medium',
    remediation_hint=(
        'Use __atomic_fetch_add or fd_bank_ref_inc for all refcount '
        'operations in shared workspaces.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if any(tok in stmt for tok in _ATOMIC_TOKENS):
                    continue
                for m in _NONATOMIC_OP.finditer(stmt):
                    field = m.group(1)
                    if field not in _REFCOUNT_FIELDS:
                        continue
                    alerts.append({
                        'code': 110,
                        'message': (
                            f"Non-atomic refcount operation on '{field}' "
                            f"in {type_entry.name}.{function.name}: {stmt[:120]}"
                        ),
                    })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

"""Rule C20 (task 120): unaligned_memory_access_ebpf.

Detects pointer-cast VM memory accesses without explicit alignment checks in
the surrounding statements.
"""
import re

from smartgraphical.core.engine import make_findings

_CAST_MEM_ACCESS = re.compile(r'\*\s*\([^)]*\*\)\s*\([^)]*(?:addr|offset)[^)]*\)')
_ALIGNMENT_GUARD_TOKENS = (
    '& 0x7',
    '& 7',
    '% 8',
    'unaligned',
    'is_aligned',
    'align_check',
)

_META = dict(
    task_id='120',
    legacy_code=120,
    slug='unaligned_memory_access_ebpf',
    title='Unaligned Memory Access in Flamenco VM',
    category='control_flow_integrity',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Check alignment for VM load/store addresses before pointer-cast '
        'dereference to match strict eBPF behavior.'
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
                if 'vm->mem' not in stmt_lower and 'vm_mem' not in stmt_lower:
                    continue
                if not _CAST_MEM_ACCESS.search(stmt):
                    continue
                lookback = stmts[max(0, idx - 3): idx]
                has_guard = any(
                    token in s.lower() for token in _ALIGNMENT_GUARD_TOKENS for s in lookback
                )
                if has_guard:
                    continue
                alerts.append({
                    'code': 120,
                    'message': (
                        f"VM memory cast access without alignment guard in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

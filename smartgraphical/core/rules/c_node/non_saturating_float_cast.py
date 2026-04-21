"""Rule C01 (task 101): non_saturating_float_cast.

Detects direct C casts from floating-point expressions to unsigned integer
types without a saturating wrapper, which produces different results from
Rust's semantics for values outside the representable range (e.g. -inf).

Scope: c_specific
Priority: 36 (highest in initial catalog)
"""
import re

from smartgraphical.core.engine import make_findings

# Matches a direct C cast to any common unsigned integer type.
_DIRECT_CAST = re.compile(
    r'\(\s*(?:ulong|uint64_t|uint32_t|uint16_t|uint8_t|unsigned\s+long'
    r'|unsigned\s+int|unsigned\s+short)\s*\)'
)

# Safe wrappers that produce Rust-compatible saturation behavior.
_SAFE_WRAPPERS = [
    'fd_rust_cast',
    'fd_saturating',
    'fd_uint_sat',
    'fd_ulong_sat',
]

_META = dict(
    task_id='101',
    legacy_code=101,
    slug='non_saturating_float_cast',
    title='Rust-Incompatible Floating Point Cast',
    category='consensus_failure',
    portability='c_specific',
    confidence='high',
    remediation_hint=(
        'Use fd_rust_cast_double_to_ulong or an equivalent saturating '
        'helper to match Rust unsigned-cast semantics.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if not _DIRECT_CAST.search(stmt):
                    continue
                if any(w in stmt for w in _SAFE_WRAPPERS):
                    continue
                alerts.append({
                    'code': 101,
                    'message': (
                        f"Non-saturating float-to-uint cast in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

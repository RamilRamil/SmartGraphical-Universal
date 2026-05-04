"""Rule C19 (task 119): division_rounding_divergence.

Detects signed division/modulo in consensus-sensitive math without explicit
protocol rounding helper usage.
"""
import re

from smartgraphical.core.engine import make_findings

_SIGNED_TOKENS = ('int ', 'long ', 'ssize_t', 'ptrdiff_t', 'debt', 'offset', 'balance')
_DIV_MOD_RE = re.compile(r'[/%]')
_SAFE_TOKENS = ('div_euclidean', 'fd_long_div_euclidean', 'fd_div_floor')
_CONSENSUS_TOKENS = ('reward', 'rent', 'runtime', 'lamport', 'stake', 'balance')

_META = dict(
    task_id='119',
    legacy_code=119,
    slug='division_rounding_divergence',
    title='Signed Division/Modulo Rounding Mismatch',
    category='consensus_failure',
    portability='portable_with_adapter',
    confidence='medium',
    remediation_hint=(
        'Use explicit helper functions that enforce protocol-required rounding '
        'semantics for signed division/modulo.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                stmt_lower = stmt.lower()
                if not _DIV_MOD_RE.search(stmt):
                    continue
                if any(token in stmt_lower for token in _SAFE_TOKENS):
                    continue
                if not any(token in stmt_lower for token in _SIGNED_TOKENS):
                    continue
                if not any(token in stmt_lower for token in _CONSENSUS_TOKENS):
                    continue
                alerts.append({
                    'code': 119,
                    'message': (
                        f"Signed division/modulo without explicit rounding helper in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

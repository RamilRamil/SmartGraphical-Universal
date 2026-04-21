"""Rule C09 (task 109): quic_handshake_eviction_missing.

Detects QUIC handshake pool exhaustion paths that return an error to the
caller without first attempting to evict a stale or incomplete handshake.
When the pool is full, a validator that immediately rejects new connection
attempts is vulnerable to a targeted flooding attack: an adversary can
occupy all handshake slots with PING frames, permanently denying service
to legitimate peers.

Heuristic (PoC level):
- Find statements that reference the handshake pool (hs_pool, fd_quic_hs).
- Look for a rejection indicator (== NULL, full, busy) in the nearby window.
- Check whether an eviction call (evict, oldest, reclaim) also appears.
- Fire if there is a rejection but no eviction in the window.

Scope: node_specific
Priority: 28
"""
import re

from smartgraphical.core.engine import make_findings

# Handshake pool reference patterns.
_HS_POOL_REF = re.compile(
    r'(?:hs_pool|handshake_pool|fd_quic_hs|conn_hs)\w*'
)

# Signals that the pool allocation failed or the pool is saturated.
_POOL_REJECTION = re.compile(
    r'==\s*NULL|==\s*0\b|is_full|pool_full|\bfull\b|\bbusy\b|ERR_BUSY|ERR_FULL'
)

# Tokens indicating an eviction strategy is present.
_EVICTION_TOKENS = ['evict', 'oldest', 'lru', 'lifo', 'expire', 'reclaim', 'displace']

_META = dict(
    task_id='109',
    legacy_code=109,
    slug='quic_handshake_eviction_missing',
    title='Missing Handshake Eviction Strategy',
    category='denial_of_service',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Implement a LIFO or oldest-incomplete eviction policy for the '
        'handshake pool when all slots are occupied before rejecting the '
        'new connection attempt.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            for idx, stmt in enumerate(stmts):
                if not _HS_POOL_REF.search(stmt):
                    continue
                # Look at nearby statements for rejection and eviction signals.
                window = stmts[max(0, idx - 1):min(len(stmts), idx + 6)]
                has_rejection = any(_POOL_REJECTION.search(s) for s in window)
                if not has_rejection:
                    continue
                has_eviction = any(
                    ev in s.lower() for ev in _EVICTION_TOKENS for s in window
                )
                if has_eviction:
                    continue
                alerts.append({
                    'code': 109,
                    'message': (
                        f"Handshake pool exhaustion rejected without eviction "
                        f"in {type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

"""Rule C14 (task 114): bls_aggregate_rogue_key_check.

Detects BLS12-381 public key aggregation calls that are not preceded by a
proof-of-possession (PoP) verification in the surrounding statement window.
Without PoP checks an adversary can craft a malicious public key that cancels
out a legitimate validator key during aggregation (rogue key attack), allowing
the adversary to forge an aggregate signature.

Heuristic (PoC level):
- Find statements containing BLS aggregation call patterns
  (bls_aggregate, bls_sum, bls12_aggregate, g1_sum, pk_aggregate, ...).
- Look in the surrounding statement window for a PoP / proof check call
  (verify_pop, check_pop, bls_verify_pop, proof_of_possession, ...).
- Flag aggregation calls where no PoP check appears in the window.

Scope: node_specific
Priority: 40
"""
import re

from smartgraphical.core.engine import make_findings

# Patterns that indicate a BLS key aggregation is being computed.
_BLS_AGGREGATE = re.compile(
    r'(?:bls(?:12)?_(?:aggregate|sum|acc|pk_add)|g1_(?:sum|add)|'
    r'pk_(?:aggregate|sum)|aggregate_pk|aggregate_key)',
    re.IGNORECASE,
)

# Tokens that indicate a proof-of-possession check is present.
_POP_TOKENS = [
    'verify_pop', 'check_pop', 'bls_verify_pop', 'proof_of_possession',
    'pop_verify', 'validate_pop', 'fd_bls_pop',
]

# How many statements to look back and forward for a PoP check.
_WINDOW_RADIUS = 6

_META = dict(
    task_id='114',
    legacy_code=114,
    slug='bls_aggregate_rogue_key_check',
    title='Missing Rogue Key Protection in Alpenglow Aggregation',
    category='cryptographic_safety',
    portability='node_specific',
    confidence='low',
    remediation_hint=(
        'Implement proof-of-possession checks for all validator public keys '
        'before admitting them to the Alpenglow voting set.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            for idx, stmt in enumerate(stmts):
                if not _BLS_AGGREGATE.search(stmt):
                    continue
                window = stmts[
                    max(0, idx - _WINDOW_RADIUS):
                    min(len(stmts), idx + _WINDOW_RADIUS + 1)
                ]
                if any(tok in s for tok in _POP_TOKENS for s in window):
                    continue
                alerts.append({
                    'code': 114,
                    'message': (
                        f"BLS key aggregation without proof-of-possession check "
                        f"in {type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

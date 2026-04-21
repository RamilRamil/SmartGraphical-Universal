"""Rule C07 (task 107): bitwise_flag_normalization_mismatch.

Detects bitwise AND with literal 1 (or 0x1) applied to known boolean-semantic
account flag fields. In C, `account->executable & 1` extracts the LSB, which
equals `!!account->executable` only when the byte is exactly 0 or 1. If the
field byte holds any non-zero value != 1 (a plausible runtime state), the two
expressions produce different bit patterns, causing Firedancer to compute a
different bank hash from Agave.

Known boolean flag fields (extend as new account layout fields are confirmed):
  executable, writable, is_native, is_signer, is_invoked, is_writable

Scope: portable_with_adapter
Priority: 36
"""
import re

from smartgraphical.core.engine import make_findings

# Flag field names whose values should be boolean-normalized before hashing.
_BOOL_FLAG_FIELDS = frozenset({
    'executable', 'writable', 'is_native', 'is_signer',
    'is_invoked', 'is_writable', 'signed', 'readable',
})

# Matches: identifier & 1  or  identifier & 0x1
_BITWISE_CAST = re.compile(r'\b(\w+)\s*&\s*(?:0x1|1)(?!\d)')

# Expressions that already perform correct boolean normalization.
_SAFE_NORMALIZATION = ['!!', '(bool)', '(int)(bool)', 'fd_bool_if', '? 1 : 0']

_META = dict(
    task_id='107',
    legacy_code=107,
    slug='bitwise_flag_normalization_mismatch',
    title='Bitwise AND for Flag Normalization in Consensus Hashes',
    category='consensus_failure',
    portability='portable_with_adapter',
    confidence='high',
    remediation_hint=(
        'Replace field & 1 with !!field or explicit (bool) cast to guarantee '
        'standard boolean normalization matching Agave behavior.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                m = _BITWISE_CAST.search(stmt)
                if not m:
                    continue
                field = m.group(1)
                if field not in _BOOL_FLAG_FIELDS:
                    continue
                if any(safe in stmt for safe in _SAFE_NORMALIZATION):
                    continue
                alerts.append({
                    'code': 107,
                    'message': (
                        f"Boolean flag '{field}' normalized with bitwise AND "
                        f"instead of !! in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

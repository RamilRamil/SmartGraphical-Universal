"""Rule C02 (task 102): unsafe_shift_external_exponent.

Detects bitwise shift operations whose exponent appears to originate from
an external source (network packet, QUIC frame, peer header) without a
preceding explicit bound check (e.g. exponent < 64). In C, shifting by a
value >= word size is undefined behavior and can cause hangs or incorrect
RTT estimation in the QUIC/networking stack.

Scope: c_specific
Priority: 18
"""
import re

from smartgraphical.core.engine import make_findings

_SHIFT_OP = re.compile(r'<<|>>')

# Member accesses via pointer suggest data from an external struct.
_EXTERNAL_SOURCE = re.compile(
    r'(?:pkt|hdr|frame|msg|buf|conn|stream|quic|net|peer)\s*->\s*\w+'
)

# Patterns that indicate a prior or inline bound check / masking.
_SAFE_PATTERNS = [
    '< 64', '<64', '<= 63', '<=63',
    '& 0x3f', '&0x3f', '& 63', '&63',
    '% 64', '%64',
]

_META = dict(
    task_id='102',
    legacy_code=102,
    slug='unsafe_shift_external_exponent',
    title='Undefined Behavior in Shift Operations from External Input',
    category='denial_of_service',
    portability='c_specific',
    confidence='high',
    remediation_hint=(
        'Validate that the shift exponent is strictly less than 64 '
        'before performing the operation.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            for idx, stmt in enumerate(stmts):
                if not _SHIFT_OP.search(stmt):
                    continue
                if not _EXTERNAL_SOURCE.search(stmt):
                    continue
                # Inline safe pattern on the same statement.
                if any(pat in stmt for pat in _SAFE_PATTERNS):
                    continue
                # Look back up to 3 statements for a bound check.
                window = stmts[max(0, idx - 3):idx]
                if any(pat in s for pat in _SAFE_PATTERNS for s in window):
                    continue
                alerts.append({
                    'code': 102,
                    'message': (
                        f"Shift with externally-sourced exponent and no "
                        f"prior bound check in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

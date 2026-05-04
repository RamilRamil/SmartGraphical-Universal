"""Rule C12 (task 112): alt_resolution_window_mismatch.

Detects ALT (Address Lookup Table) deactivation-slot comparisons that use
a numeric literal other than the Agave-compatible 512-slot window. Using a
different window causes the resolve tile to accept or reject transactions
differently from Agave, producing consensus divergence.

Heuristic (PoC level):
- Find statements that mention ALT-related keywords (alt, deactivation_slot,
  lookup_table, lut).
- Look for a numeric constant in the same statement that participates in a
  comparison (>, >=, <, <=).
- Flag the constant if it is not 512.

Scope: node_specific
Priority: 15
"""
import re

from smartgraphical.core.engine import make_findings

# ALT / lookup table domain keywords.
_ALT_KEYWORDS = [
    'deactivation_slot', 'alt_slot', 'lookup_table', 'lut_slot',
    'alt_deactivat', 'lut_deactivat',
]

# Numeric literal in a slot-distance comparison (not a hex address).
_SLOT_CONSTANT = re.compile(r'(?:>|>=|<|<=)\s*(\d+)\b')

# The single correct Agave-compatible window constant.
_CORRECT_WINDOW = 512

_META = dict(
    task_id='112',
    legacy_code=112,
    slug='alt_resolution_window_mismatch',
    title='Incorrect ALT Resolution Slot Window',
    category='correctness',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Use exactly 512 as the slot lookback window in ALT resolution '
        'to match Agave inclusion semantics.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if not any(kw in stmt for kw in _ALT_KEYWORDS):
                    continue
                for m in _SLOT_CONSTANT.finditer(stmt):
                    constant = int(m.group(1))
                    if constant == _CORRECT_WINDOW:
                        continue
                    alerts.append({
                        'code': 112,
                        'message': (
                            f"ALT slot window uses constant {constant} "
                            f"instead of {_CORRECT_WINDOW} in "
                            f"{type_entry.name}.{function.name}: {stmt[:120]}"
                        ),
                    })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

"""Rule C08 (task 108): quic_invisible_frame_limit.

Detects QUIC frame processing calls inside loops that lack a per-packet
frame count cap in the surrounding statement window. Protocol-level frames
(PING, PADDING, ACK) are invisible to the application layer: they consume
CPU without advancing the application's credit counter. An attacker can
craft packets containing only such frames and exhaust CPU resources.

Heuristic (PoC level):
- Find statements containing frame processing keywords.
- Look back a few statements to confirm the processing is inside a loop.
- Check the surrounding window for a resource limit token.
- Fire if no limit is found.

Scope: node_specific
Priority: 40 (highest in catalog)
"""
import re

from smartgraphical.core.engine import make_findings

# Frame processing call patterns.
_FRAME_PROCESSING = re.compile(
    r'(?:parse|handle|process)[_\w]*\s*\(.*(?:frame|packet)'
    r'|(?:frame|packet)[_\w]*\s*\(.*(?:parse|handle|process)'
    r'|(?:frame|packet).*(?:parse|handle|process)',
    re.IGNORECASE,
)

# Loop indicators to look back for.
_LOOP_INDICATOR = re.compile(r'\b(?:while|for)\b')

# Tokens that indicate a per-packet frame budget is enforced.
_LIMIT_TOKENS = [
    'MAX_FRAMES', 'max_frames', 'frame_count', 'frame_limit',
    'frames_per_packet', 'frame_budget', 'fd_quic_max_frame',
    'frame_cap', 'frame_remaining',
]

_META = dict(
    task_id='108',
    legacy_code=108,
    slug='quic_invisible_frame_limit',
    title='Missing Limit on Invisible QUIC Protocol Frames',
    category='denial_of_service',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Implement a counter to limit the number of protocol frames '
        'consumed per single UDP packet, for example frame_count < MAX_FRAMES.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            for idx, stmt in enumerate(stmts):
                if not _FRAME_PROCESSING.search(stmt):
                    continue
                # Confirm we are inside a loop by looking back up to 5 stmts.
                lookback = stmts[max(0, idx - 5):idx]
                if not any(_LOOP_INDICATOR.search(s) for s in lookback):
                    continue
                # Check the surrounding window for a frame budget token.
                window = stmts[max(0, idx - 5):min(len(stmts), idx + 3)]
                if any(token in s for token in _LIMIT_TOKENS for s in window):
                    continue
                alerts.append({
                    'code': 108,
                    'message': (
                        f"Frame processing loop without per-packet frame limit "
                        f"in {type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

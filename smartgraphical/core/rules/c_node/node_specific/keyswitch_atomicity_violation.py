"""Rule C13 (task 113): keyswitch_atomicity_violation.

Detects invalid ordering in identity switch flow. Expected order:
HALT -> FLUSH -> UPDATE -> RESUME.

This rule uses ordered call facts extracted by the C adapter.
"""

from smartgraphical.core.engine import make_findings

_HALT_MARKERS = ('poh_halt', 'halt_poh', 'fd_poh_halt', 'poh_pause')
_FLUSH_MARKERS = ('shred_flush', 'flush_shred', 'fd_shred_flush')
_UPDATE_MARKERS = (
    'update_sign_tile', 'set_identity', 'update_signer', 'set_signer',
    'keyswitch_update_sign', 'sign_tile_update',
)

_META = dict(
    task_id='113',
    legacy_code=113,
    slug='keyswitch_atomicity_violation',
    title='Non-Atomic Identity Switch Coordination',
    category='liveness',
    portability='node_specific',
    confidence='medium',
    remediation_hint='Enforce HALT -> FLUSH -> UPDATE -> RESUME ordering.',
)


def _first_index(calls, markers):
    for idx, call in enumerate(calls):
        lowered = call.lower()
        if any(marker in lowered for marker in markers):
            return idx
    return -1


def _detect(context):
    alerts = []
    model = context.normalized_model
    function_facts = getattr(model.findings_data, 'function_facts', {})
    for type_entry in model.types:
        for function in type_entry.functions:
            function_key = f"{type_entry.name}.{function.name}"
            facts = function_facts.get(function_key, {})
            ordered_call_facts = facts.get('dataflow', {}).get('ordered_calls', [])
            call_names = [entry.get('call', '') for entry in ordered_call_facts]
            if not call_names:
                continue
            update_idx = _first_index(call_names, _UPDATE_MARKERS)
            if update_idx < 0:
                continue
            halt_idx = _first_index(call_names, _HALT_MARKERS)
            flush_idx = _first_index(call_names, _FLUSH_MARKERS)
            if halt_idx < 0 or flush_idx < 0:
                alerts.append({
                    'code': 113,
                    'message': (
                        f"Keyswitch update observed without full HALT/FLUSH sequence "
                        f"in {function_key}."
                    ),
                })
                continue
            if update_idx < halt_idx or update_idx < flush_idx:
                alerts.append({
                    'code': 113,
                    'message': (
                        f"Keyswitch order violation (update before halt/flush) "
                        f"in {function_key}."
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

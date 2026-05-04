"""Rule C11 (task 111): io_uring_submission_race_funk.

Detects io_uring submit calls that target a likely shared ring without an
explicit synchronization marker. This rule relies on dataflow facts produced
by the C adapter under findings_data.function_facts[function_key]["dataflow"].

PoC heuristic:
- locate io_uring_submit sites from adapter facts;
- flag site when ring expression is not private and appears shared/global;
- suppress when nearby lock/guard markers are present.
"""

from smartgraphical.core.engine import make_findings

_META = dict(
    task_id='111',
    legacy_code=111,
    slug='io_uring_submission_race_funk',
    title='Race Condition in Funk Database io_uring Submissions',
    category='data_integrity',
    portability='c_specific',
    confidence='low',
    remediation_hint=(
        'Use a private io_uring instance per tile or enforce explicit '
        'synchronization around shared ring submission.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    function_facts = getattr(model.findings_data, 'function_facts', {})
    for type_entry in model.types:
        for function in type_entry.functions:
            function_key = f"{type_entry.name}.{function.name}"
            facts = function_facts.get(function_key, {})
            dataflow = facts.get('dataflow', {})
            submit_sites = dataflow.get('io_uring_submit_sites', [])
            has_tile_context = bool(dataflow.get('tile_markers', []))
            for site in submit_sites:
                if site.get('is_private'):
                    continue
                if site.get('is_guarded'):
                    continue
                ring_expr = site.get('ring_expr', '')
                if not (site.get('is_shared') or has_tile_context):
                    continue
                alerts.append({
                    'code': 111,
                    'message': (
                        f"io_uring_submit on potentially shared ring '{ring_expr}' "
                        f"without synchronization in {function_key}: "
                        f"{site.get('statement', '')[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

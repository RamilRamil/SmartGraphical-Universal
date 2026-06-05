"""Portable rule: untrusted input reaches a sensitive sink without a guard.

Consumes the additive `NormalizedFunction.taint_paths` produced by the
intra-procedural taint pass (feature 015). Heuristic: a hypothesis at medium
confidence, never a proof (constitution Principle II).
"""
from smartgraphical.core.engine import make_findings

_META = dict(
    task_id="taint",
    legacy_code=0,
    slug="tainted_input_unguarded_sink",
    title="Untrusted input reaches a sensitive sink without a guard",
    category="dataflow",
    portability="portable",
    confidence="medium",
    remediation_hint=(
        "Validate or guard untrusted input before it reaches the sink "
        "(heuristic intra-procedural taint; review the source->sink path)."
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for path in (getattr(function, "taint_paths", None) or []):
                if path.get("guarded"):
                    continue
                alerts.append({
                    "code": 0,
                    "message": (
                        f"Untrusted '{path.get('source')}' reaches sink "
                        f"'{path.get('sink')}' in {type_entry.name}.{function.name} "
                        f"without a guard: {str(path.get('sink_stmt', ''))[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

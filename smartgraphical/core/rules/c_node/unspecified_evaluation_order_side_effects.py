"""Rule C17 (task 117): unspecified_evaluation_order_side_effects.

Detects call expressions with multiple nested side-effecting call arguments.
In C the argument evaluation order is unspecified, which can cause divergent
state transitions compared to deterministic evaluation models.
"""
import re

from smartgraphical.core.engine import make_findings

_CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
_SIDE_EFFECT_TOKENS = (
    'update', 'set_', 'write', 'store', 'hash', 'commit',
    'apply', 'mutate', 'push', 'pop',
)

_META = dict(
    task_id='117',
    legacy_code=117,
    slug='unspecified_evaluation_order_side_effects',
    title='Unspecified Order of Evaluation with Side Effects',
    category='correctness',
    portability='c_specific',
    confidence='medium',
    remediation_hint=(
        'Evaluate side-effecting calls into temporary variables in explicit '
        'order before parent call invocation.'
    ),
)


def _split_top_level_args(args_text):
    args = []
    current = []
    depth = 0
    for ch in args_text:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        args.append(tail)
    return args


def _extract_outer_args(stmt):
    open_idx = stmt.find('(')
    close_idx = stmt.rfind(')')
    if open_idx < 0 or close_idx <= open_idx:
        return []
    return _split_top_level_args(stmt[open_idx + 1:close_idx])


def _has_side_effect_call(expr):
    match = _CALL_RE.search(expr)
    if not match:
        return False
    call_name = match.group(1).lower()
    return any(token in call_name for token in _SIDE_EFFECT_TOKENS)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                args = _extract_outer_args(stmt)
                if len(args) < 2:
                    continue
                side_effect_args = [arg for arg in args if _has_side_effect_call(arg)]
                if len(side_effect_args) < 2:
                    continue
                alerts.append({
                    'code': 117,
                    'message': (
                        f"Multiple side-effect call arguments with unspecified "
                        f"evaluation order in {type_entry.name}.{function.name}: "
                        f"{stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

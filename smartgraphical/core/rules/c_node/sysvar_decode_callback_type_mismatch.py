"""Rule C06 (task 106): sysvar_decode_callback_type_mismatch.

Detects assignments to sysvar decode callback function pointers that use
an explicit type cast, which is the canonical C sign that the compiler
detected a type mismatch and the programmer silenced it instead of fixing
the signature.

Detection: scan exploration_statements for patterns of the form
  <obj>->decode = (<cast>) <func>
where <cast> is any explicit type cast (void *, fd_*_fn_t, etc.).
A correct assignment has no cast:
  sysvar->decode = my_decode_func;

Static type signature check (PoC level): the rule fires when a cast is
present; the auditor must verify whether the cast is a genuine mismatch or
a deliberate opaque-pointer pattern.

Scope: node_specific
Priority: 21
"""
import re

from smartgraphical.core.engine import make_findings

# Assignment to any ->decode member.
_DECODE_ASSIGN = re.compile(r'->\s*decode\s*=')

# Any explicit C cast: ( type ) or ( type * ) before the assigned value.
_EXPLICIT_CAST = re.compile(
    r'=\s*\(\s*'          # = (
    r'(?:void\s*\*|'      # void *
    r'fd_\w+_fn_t\s*\*?|' # fd_*_fn_t
    r'\w+\s*\*)'          # any other pointer type
    r'\s*\)'              # )
)

_META = dict(
    task_id='106',
    legacy_code=106,
    slug='sysvar_decode_callback_type_mismatch',
    title='Function Type Mismatch in Sysvar Decode Callbacks',
    category='control_flow_integrity',
    portability='node_specific',
    confidence='high',
    remediation_hint=(
        'Ensure the decode callback signature matches the typedef in '
        'fd_sysvar_cache.h exactly. Remove the explicit cast and fix the '
        'function signature instead.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if not _DECODE_ASSIGN.search(stmt):
                    continue
                if not _EXPLICIT_CAST.search(stmt):
                    continue
                alerts.append({
                    'code': 106,
                    'message': (
                        f"Sysvar decode callback assigned with explicit type cast "
                        f"(possible signature mismatch) in "
                        f"{type_entry.name}.{function.name}: {stmt[:120]}"
                    ),
                })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

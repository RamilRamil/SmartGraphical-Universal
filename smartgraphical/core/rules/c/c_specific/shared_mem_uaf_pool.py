"""Rule C04 (task 104): shared_mem_uaf_pool.

Detects use-after-free patterns in shared memory pools: a pointer passed
to a pool release function is dereferenced in a subsequent statement
without being re-assigned (nullified) first.

Heuristic (PoC level):
- Detect release calls by name prefix (fd_*_release, fd_wksp_free, fd_alloc_free).
- Extract the first identifier argument as the released variable.
- Walk subsequent statements looking for pointer dereference of that variable.
- Suppress if the variable is re-assigned (including to NULL) before the deref.

Scope: c_specific
Priority: 27
"""
import re

from smartgraphical.core.engine import make_findings

# Release API name prefixes / exact names.
_RELEASE_PATTERN = re.compile(
    r'(?:fd_\w+_release|fd_wksp_free|fd_alloc_free|fd_pool_release)\s*\(\s*(\w+)'
)

# Dereference of a named variable: `var->`, `var[`, `(*var)`
def _is_deref(stmt, var):
    return bool(
        re.search(rf'\b{re.escape(var)}\s*(?:->|\[)', stmt)
        or f'*{var}' in stmt
    )

# Safe re-assignment (nullification or any assignment).
def _is_nullified(stmt, var):
    return bool(re.search(rf'\b{re.escape(var)}\s*=', stmt))

_META = dict(
    task_id='104',
    legacy_code=104,
    slug='shared_mem_uaf_pool',
    title='Use-After-Free in Shared Memory Pools',
    category='memory_safety',
    portability='c_specific',
    confidence='medium',
    remediation_hint=(
        'Nullify the pointer immediately after releasing it to the pool '
        '(e.g. elem = NULL) and validate ownership before any further access.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            stmts = function.exploration_statements
            # released_vars: var_name -> index of release statement
            released_vars = {}

            for idx, stmt in enumerate(stmts):
                # Check for a new release call.
                m = _RELEASE_PATTERN.search(stmt)
                if m:
                    released_vars[m.group(1)] = idx
                    continue

                for var, release_idx in list(released_vars.items()):
                    if idx <= release_idx:
                        continue
                    if _is_nullified(stmt, var):
                        # Pointer is re-assigned; no longer dangerous.
                        del released_vars[var]
                    elif _is_deref(stmt, var):
                        alerts.append({
                            'code': 104,
                            'message': (
                                f"Use-after-free: '{var}' dereferenced after "
                                f"pool release in "
                                f"{type_entry.name}.{function.name}: {stmt[:120]}"
                            ),
                        })
                        # Remove to avoid duplicate alerts for the same var.
                        del released_vars[var]
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

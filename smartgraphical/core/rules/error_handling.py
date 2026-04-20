"""Task 6: try/catch exception handling checks."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import extract_asserts
from smartgraphical.core.engine import make_findings


def exceptions(rets):
    """Task 6 - detect unhandled exceptions and revert patterns in try/catch."""
    alerts = []
    all_funcs = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dvars]
        all_funcs.extend(dvars)

    for i in range(len(all_funcs)):
        f_body = all_funcs[i][4]
        var_inds = [m.start() for m in re.finditer('try', f_body)]
        try_catches = []
        for k in range(len(var_inds)):
            temp = []
            for j in range(len(f_body)):
                eol = None
                par_iter = 0
                par_ind = f_body[var_inds[k]:].index('{')
                for j in range(var_inds[k] + par_ind + 1, len(f_body)):
                    if f_body[j] == "}":
                        par_iter -= 1
                    if f_body[j] == "{":
                        par_iter += 1
                    if par_iter == -1:
                        eol = j
                        break
            temp.append(f_body[var_inds[k]:eol + 1])
            rest = f_body[eol + 1:].strip()
            if rest[:len('catch')] == 'catch':
                for j in range(len(rest)):
                    eol2 = None
                    par_iter = 0
                    par_ind = rest.index('{')
                    for j in range(par_ind + 1, len(rest)):
                        if rest[j] == "}":
                            par_iter -= 1
                        if rest[j] == "{":
                            par_iter += 1
                        if par_iter == -1:
                            eol2 = j
                            break
                temp.append(rest[:eol2 + 1])
            try_catches.append(temp)

        for j in range(len(try_catches)):
            if len(try_catches[j]) == 2:
                if "revert" in try_catches[j][1]:
                    alerts.append({
                        'code': 6,
                        'message': f"Alert: Revert action found in line: {try_catches[j][1]}"
                    })
                asserts = extract_asserts([try_catches[j][1]])[0]
                if len(asserts) > 0:
                    alerts.append({'code': 6, 'message': f"Alert: asserts:  {asserts}"})
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='6', legacy_code=6, slug='exceptions',
    title='Error Path Consistency', category='FlowAndOrdering',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Inspect try/catch handlers and ensure the error path preserves valid state transitions.',
)


def run(context):
    alerts = exceptions(context.rets)
    return make_findings(alerts, context.normalized_model, **_META)

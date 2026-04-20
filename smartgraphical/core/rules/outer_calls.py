"""Task 12: outer_calls - unguarded external functions manipulating inputs."""
import re

from smartgraphical.adapters.solidity.helpers import intra_contract_connection
from smartgraphical.core.engine import make_findings


def outer_calls(rets, reader, high_connections):
    """Task 12 - detect external functions that use input params without guards."""
    alerts = []
    all_maps = {}
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        all_maps[contract_name] = func_func_mapping

    for k, v in all_maps.items():
        for kk, vv in v.items():
            if len(vv) == 0:
                funcs = reader.contracts_mem[k]['funcs']
                func_names = [item[0] for item in funcs]
                if kk in func_names:
                    if intra_contract_connection(high_connections, kk):
                        continue
                    func_ind = func_names.index(kk)
                    func = funcs[func_ind]
                    if 'external' in func[2]:
                        only_flag = any('only' in j for j in func[2])
                        if not only_flag:
                            input_params = func[1]
                            if input_params == [['']]:
                                continue
                            for var in input_params:
                                if var[-1] in func[3]:
                                    var_inds = [m.start() for m in re.finditer(var[-1], func[3])]
                                    for i in range(len(var_inds)):
                                        bol = None
                                        for j in range(var_inds[i], 0, -1):
                                            if func[3][j] == ";":
                                                bol = j + 1
                                                break
                                        if bol is None:
                                            bol = 1
                                        eol = None
                                        for j in range(var_inds[i], len(func[3])):
                                            if func[3][j] == ";":
                                                eol = j
                                                break
                                        if eol is None:
                                            eol = len(func[3]) - 1
                                        temp = func[3][bol:eol + 1]
                                        temp = temp.replace(reader.line_sep, '').strip()
                                        if ('return' in temp) or ('if' in temp) or ('require' in temp) or ('emit' in temp):
                                            continue
                                        alerts.append({
                                            'code': 12,
                                            'message': f"Outer manipulation in function {kk}, line: {temp}"
                                        })
    return alerts


def _outer_calls_from_normalized(context):
    """Normalized-first outer call checks (Phase 3)."""
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            # Keep the original intent: external entrypoints with inputs and state mutation,
            # but without explicit guards/permissions should be reviewed.
            if function.visibility != 'external':
                continue
            if not function.is_entrypoint:
                continue
            if not function.inputs or function.inputs == [['']]:
                continue
            if not function.mutations:
                continue
            has_guard = bool(function.guard_facts or function.guards)
            has_permission = bool(function.entrypoint_permissions)
            if has_guard or has_permission:
                continue
            first_mutation = function.mutations[0]
            alerts.append({
                'code': 12,
                'message': (
                    f"Outer manipulation in function {type_entry.name}.{function.name}, "
                    f"line: {first_mutation}"
                ),
            })
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='11', legacy_code=12, slug='outer_calls',
    title='Outer Calls', category='StateAndMutation',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Review public entrypoints that consume inputs and mutate state without stronger constraints.',
)


def run(context):
    alerts = _outer_calls_from_normalized(context)
    return make_findings(alerts, context.normalized_model, **_META)

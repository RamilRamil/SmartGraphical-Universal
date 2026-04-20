"""Task 7: complicated calculations checks."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import similar_string, find_uniques
from smartgraphical.core.engine import make_findings


def complicated_calculations(rets, reader):
    """Task 7 - detect risky math patterns (.mul/.div, nested parentheses)."""
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(vars)
        x = [item.insert(0, contract_name) for item in dvars]
        all_vars.extend(dvars)
        if len(funcs) > 0:
            dfuncs = []
            for j in deepcopy(funcs):
                if j[1] != [['']]:
                    x = [item.insert(0, contract_name) for item in j[1]]
                    dfuncs.extend(j[1])
            all_vars.extend(dfuncs)

    all_vars = find_uniques(all_vars)
    unallowed_vars = []

    for una_var in unallowed_vars:
        var_names = [item[-1] for item in all_vars]
        corresponding_contract = None
        current_var_name = ''
        if una_var in var_names:
            if var_names.count(una_var) > 1:
                ind = var_names.index(una_var)
                corresponding_contract = all_vars[ind][0]
                current_var_name = var_names[ind]
            else:
                ind = var_names.index(una_var)
                corresponding_contract = all_vars[ind][0]
                current_var_name = var_names[ind]
        else:
            sim = similar_string(una_var, var_names)
            if sim is None:
                continue
            current_var_name = sim
            ind = var_names.index(current_var_name)
            corresponding_contract = all_vars[ind][0]

        if corresponding_contract is not None:
            susceptible_vars = [current_var_name]
            funcs = reader.contracts_mem[corresponding_contract]['funcs']
            bodies = [item[-1] for item in funcs]
            for sus in susceptible_vars:
                for bb in range(len(bodies)):
                    t = sus
                    var_inds = [m.start() for m in re.finditer(t, bodies[bb])]
                    for i in range(len(var_inds)):
                        bol = None
                        for j in range(var_inds[i], 0, -1):
                            if bodies[bb][j] == ";":
                                bol = j + 1
                                break
                        if bol is None:
                            bol = 1
                        eol = None
                        for j in range(var_inds[i], len(bodies[bb])):
                            if bodies[bb][j] == ";":
                                eol = j
                                break
                        if eol is None:
                            eol = len(bodies[bb]) - 1
                        temp = bodies[bb][bol:eol + 1]
                        temp = temp.replace(reader.line_sep, '').strip()
                        if '.mul' in temp and '.div' in temp:
                            alerts.append({
                                'code': 7,
                                'message': f"Alert: Multiplication and division occured simultaneously in line: {temp}"
                            })
                        if '.div' in temp:
                            alerts.append({'code': 7, 'message': f"Alert: Division is occured in line: {temp}"})

    for k, v in reader.contracts_mem.items():
        funcs = v['funcs']
        bodies = [item[-1] for item in funcs]
        for bb in range(len(bodies)):
            lines = bodies[bb].split(";")
            for temp in lines:
                if '.mul' in temp and '.div' in temp:
                    alerts.append({
                        'code': 7,
                        'message': f"Alert: Multiplication and division occured simultaneously in line: {temp}"
                    })
                if 'math.' in temp:
                    alerts.append({'code': 7, 'message': f"Alert: Math functions are used in line: {temp}"})
                brack_iter = 0
                start_flag = 0
                if '(' in temp:
                    s_ind = temp.index('(')
                    for i in range(s_ind, len(temp)):
                        if temp[i] == "(":
                            brack_iter += 1
                            start_flag = 1
                            if brack_iter >= 2 and (('.mul' in temp) or ('.div' in temp) or ('.sub' in temp) or ('.add' in temp)):
                                alerts.append({
                                    'code': 7,
                                    'message': f"Alert: Complicated parenthesis are used in line: {temp}"
                                })
                                break
                            continue
                        if temp[i] == ")":
                            brack_iter -= 1
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='7', legacy_code=7, slug='complicated_calculations',
    title='Complicated Calculations', category='ComputationAndEconomics',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Review arithmetic-heavy expressions and simplify or guard the most complex branches.',
)


def run(context):
    alerts = complicated_calculations(context.rets, context.reader)
    return make_findings(alerts, context.normalized_model, **_META)

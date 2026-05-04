"""Task 3: staking / unstaking pattern checks."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import extract_requirements, extract_operation
from smartgraphical.core.engine import make_findings


def staking(rets):
    """Task 3 - verify stake/unstake balance manipulation."""
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        temp = deepcopy(funcs)
        [item.insert(0, contract_name) for item in temp]
        all_vars.extend(temp)

    stake_vars = ['stake']
    stake_func_name = None
    for stk in stake_vars:
        for i in range(len(all_vars)):
            reqs = extract_requirements([all_vars[i][-1]])
            new_body = deepcopy(all_vars[i][-1])
            for j in range(len(reqs[0])):
                new_body = all_vars[i][-1].replace(reqs[0][j], '')
            var_inds = [m.start() for m in re.finditer(' ' + stk, new_body)]
            if len(var_inds) > 0:
                alerts.append({
                    'code': 3,
                    'message': f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function."
                })
            if stk in all_vars[i][1]:
                alerts.append({
                    'code': 3,
                    'message': f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract."
                })
                if stk == 'stake' and stake_func_name is None:
                    stake_func_name = [all_vars[i][1], all_vars[i][2], all_vars[i][4]]

    if stake_func_name is None:
        return alerts

    unstake_func_name = None
    unstake_vars = ['unstake']
    for stk in unstake_vars:
        for i in range(len(all_vars)):
            reqs = extract_requirements([all_vars[i][-1]])
            new_body = deepcopy(all_vars[i][-1])
            for j in range(len(reqs[0])):
                new_body = all_vars[i][-1].replace(reqs[0][j], '')
            var_inds = [m.start() for m in re.finditer(' ' + stk, new_body)]
            if len(var_inds) > 0:
                alerts.append({
                    'code': 3,
                    'message': f"Variable '{stk}' is used in '{all_vars[i][0]}' contract, '{all_vars[i][1]}' function."
                })
            if stk in all_vars[i][1]:
                alerts.append({
                    'code': 3,
                    'message': f"Function '{all_vars[i][1]}' is related to '{stk}' in '{all_vars[i][0]}' contract."
                })
                if stk == 'unstake' and unstake_func_name is None:
                    unstake_func_name = [all_vars[i][1], all_vars[i][2], all_vars[i][4]]

    if stake_func_name is not None and unstake_func_name is None:
        alerts.append({'code': 3, 'message': "No unstake function provided, while staking function exists."})

    if stake_func_name is not None:
        stake_man = extract_operation(stake_func_name[1][0][-1], stake_func_name[2])
        for item in stake_man:
            if ('+' in item) or ('+=' in item):
                alerts.append({
                    'code': 3,
                    'message': f"In stake function {stake_func_name[0]}, Manipulation in line '{item}'."
                })

    if unstake_func_name is not None:
        unstake_man = extract_operation(unstake_func_name[1][0][-1], unstake_func_name[2])
        for item in unstake_man:
            if ('-' in item) or ('-=' in item):
                alerts.append({
                    'code': 3,
                    'message': f"In stake function {unstake_func_name[0]}, Manipulation in line '{item}'."
                })
    return alerts


def _staking_from_normalized(context):
    """Normalized-first stake/unstake symmetry checks (Phase 3)."""
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        stake_functions = []
        unstake_functions = []
        for function in type_entry.functions:
            lowered_name = function.name.lower()
            if 'stake' in lowered_name and 'unstake' not in lowered_name:
                stake_functions.append(function)
                alerts.append({
                    'code': 3,
                    'message': (
                        f"Function '{function.name}' is related to 'stake' in '{type_entry.name}' contract."
                    ),
                })
            if 'unstake' in lowered_name:
                unstake_functions.append(function)
                alerts.append({
                    'code': 3,
                    'message': (
                        f"Function '{function.name}' is related to 'unstake' in '{type_entry.name}' contract."
                    ),
                })
            for statement in function.exploration_statements:
                lowered_statement = statement.lower()
                if ' stake' in lowered_statement:
                    alerts.append({
                        'code': 3,
                        'message': (
                            f"Variable 'stake' is used in '{type_entry.name}' contract, "
                            f"'{function.name}' function."
                        ),
                    })
                if ' unstake' in lowered_statement:
                    alerts.append({
                        'code': 3,
                        'message': (
                            f"Variable 'unstake' is used in '{type_entry.name}' contract, "
                            f"'{function.name}' function."
                        ),
                    })

        if stake_functions and not unstake_functions:
            alerts.append({
                'code': 3,
                'message': "No unstake function provided, while staking function exists.",
            })

        for function in stake_functions:
            for mutation in function.mutations:
                if ('+=' in mutation) or (' + ' in mutation):
                    alerts.append({
                        'code': 3,
                        'message': f"In stake function {function.name}, Manipulation in line '{mutation}'.",
                    })

        for function in unstake_functions:
            for mutation in function.mutations:
                if ('-=' in mutation) or (' - ' in mutation):
                    alerts.append({
                        'code': 3,
                        'message': f"In stake function {function.name}, Manipulation in line '{mutation}'.",
                    })
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='3', legacy_code=3, slug='staking',
    title='Stake And Release Logic', category='ComputationAndEconomics',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Verify that stake and release paths are symmetric and guard the manipulated amount.',
)


def run(context):
    alerts = _staking_from_normalized(context)
    return make_findings(alerts, context.normalized_model, **_META)

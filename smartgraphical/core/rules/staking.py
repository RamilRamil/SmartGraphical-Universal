"""Task 3: staking / unstaking pattern checks."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import extract_requirements, extract_operation


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

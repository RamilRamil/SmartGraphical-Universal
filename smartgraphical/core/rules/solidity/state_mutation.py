"""Task 2: unallowed manipulation. Task 4: pool interactions (mint/burn)."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import similar_string, extract_requirements
from smartgraphical.core.engine import make_findings


def unallowed_manipulation(rets, reader):
    """Task 2 - detect unguarded mutations of sensitive state variables."""
    alerts = []
    all_vars = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(vars)
        x = [item.insert(0, contract_name) for item in dvars]
        all_vars.extend(dvars)

    unallowed_vars = ['totalSupply', 'balance', 'fee']
    for una_var in unallowed_vars:
        current_var_name = ''
        var_default_name = una_var
        var_names = [i[-1] for i in all_vars]
        corresponding_contract = None
        if var_default_name in var_names:
            if var_names.count(var_default_name) > 1:
                alerts.append({'code': 2, 'message': "Alert: multiple definitions of total supply"})
                ind = var_names.index(var_default_name)
                corresponding_contract = all_vars[ind][0]
                current_var_name = var_names[ind]
            else:
                ind = var_names.index(var_default_name)
                corresponding_contract = all_vars[ind][0]
                current_var_name = var_names[ind]
        else:
            sim = similar_string(una_var, var_names)
            if sim is None:
                continue
            current_var_name = sim
            ind = var_names.index(current_var_name)
            corresponding_contract = all_vars[ind][0]

        prev_alerts = []
        prev_reqs = []
        if corresponding_contract is not None:
            susceptible_vars = [current_var_name, 'supply', 'amount', 'fee']
            funcs = reader.contracts_mem[corresponding_contract]['funcs']
            bodies = [i[-1] for i in funcs]
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
                        if "require" in temp:
                            if temp not in prev_reqs:
                                prev_reqs.append(temp)
                            continue
                        for f_par in range(len(funcs[bb][1])):
                            if len(funcs[bb][1][f_par]) > 1:
                                if funcs[bb][1][f_par][1] in temp:
                                    if [sus, temp] in prev_alerts:
                                        continue
                                    req_flag = any(sus in req_var for req_var in prev_reqs)
                                    if req_flag:
                                        continue
                                    if "after" in temp and "transfer" in temp:
                                        continue
                                    if "before" in temp and "transfer" in temp:
                                        continue
                                    if "return " in temp or "require(" in temp:
                                        continue
                                    prev_alerts.append([sus, temp])
                                    alerts.append({
                                        'code': 2,
                                        'message': f"Alert: Some value has been assigned to {sus} from function inputs in line: {temp}"
                                    })
    return alerts


def pool_interactions(rets):
    """Task 4 - inspect mint and burn functions for risky access patterns."""
    alerts = []
    all_funcs = []
    all_conditionals = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dvars]
        all_funcs.extend(dvars)
        all_conditionals.extend(func_conditionals)

    mint_names = ["mint"]
    for var in mint_names:
        for j in range(len(all_funcs)):
            if var in all_funcs[j][1]:
                if 'external' in all_funcs[j][3]:
                    flag = True
                    for k in all_funcs[j][3]:
                        if 'only' in k:
                            flag = False
                    if flag:
                        alerts.append({'code': 4, 'message': "Alert: Mint function is external"})
                if len(all_conditionals[j]) > 0:
                    for c in all_conditionals[j]:
                        alerts.append({'code': 4, 'message': f"Mint function: Condition: {c}"})

    burn_names = ["burn"]
    for var in burn_names:
        for j in range(len(all_funcs)):
            if var in all_funcs[j][1]:
                if 'external' in all_funcs[j][3]:
                    alerts.append({'code': 4, 'message': "Alert: Burn function is external"})
                if len(all_conditionals[j]) > 0:
                    for c in all_conditionals[j]:
                        alerts.append({'code': 4, 'message': f"Burn Condition: {c}"})
                lines = all_funcs[j][4].split(";")
                for ln in lines:
                    if 'address(0)' in ln:
                        alerts.append({'code': 4, 'message': f"zero address is used in line: {ln}"})
    return alerts


def _unallowed_manipulation_from_normalized(context):
    """Normalized-first check for risky state mutation patterns."""
    alerts = []
    model = context.normalized_model
    sensitive_tokens = ['totalsupply', 'balance', 'fee', 'amount', 'supply']
    for type_entry in model.types:
        for function in type_entry.functions:
            if not function.mutations:
                continue
            if not function.inputs or function.inputs == [['']]:
                continue
            if function.entrypoint_permissions:
                continue
            has_guard = bool(function.guard_facts or function.guards)
            if has_guard:
                continue
            for mutation in function.mutations:
                lowered = mutation.lower()
                if any(token in lowered for token in sensitive_tokens):
                    alerts.append({
                        'code': 2,
                        'message': (
                            f"Alert: Some value has been assigned to sensitive state from "
                            f"function inputs in {type_entry.name}.{function.name}, line: {mutation}"
                        ),
                    })
                    break
    return alerts


def _pool_interactions_from_normalized(context):
    """Normalized-first check for mint/burn entrypoint safety."""
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            lowered_name = function.name.lower()
            if ('mint' not in lowered_name) and ('burn' not in lowered_name):
                continue
            if function.visibility == 'external' and not function.entrypoint_permissions:
                alerts.append({
                    'code': 4,
                    'message': (
                        f"Alert: {function.name} function is external without explicit permissions "
                        f"in {type_entry.name}.{function.name}"
                    ),
                })
            if function.guard_facts:
                for guard_fact in function.guard_facts:
                    alerts.append({
                        'code': 4,
                        'message': f"{function.name} function: Condition: {guard_fact.expression}",
                    })
            if 'burn' in lowered_name:
                for statement in function.exploration_statements:
                    if 'address(0)' in statement:
                        alerts.append({
                            'code': 4,
                            'message': f"zero address is used in line: {statement}",
                        })
    return alerts


# ---------------------------------------------------------------------------
# Rule contracts (Phase 2)
# ---------------------------------------------------------------------------

_META_UNALLOWED = dict(
    task_id='2', legacy_code=2, slug='unallowed_manipulation',
    title='External State Manipulation', category='StateAndMutation',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Check assignments sourced from inputs or external values before they update sensitive state.',
)

_META_POOL = dict(
    task_id='4', legacy_code=4, slug='pool_interactions',
    title='Pool Supply Operations', category='StateAndMutation',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Review mint or burn style flows for missing access control and accounting assumptions.',
)


def run_unallowed_manipulation(context):
    alerts = _unallowed_manipulation_from_normalized(context)
    return make_findings(alerts, context.normalized_model, **_META_UNALLOWED)


def run_pool_interactions(context):
    alerts = _pool_interactions_from_normalized(context)
    return make_findings(alerts, context.normalized_model, **_META_POOL)

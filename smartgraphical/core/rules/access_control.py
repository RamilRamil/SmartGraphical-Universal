"""Task 5: local points / unchecked balance checks."""
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import extract_requirements
from smartgraphical.core.engine import make_findings


def local_points(rets):
    """Task 5 - verify that receive/take/burn functions check allowance/balance."""
    alerts = []
    for i in range(len(rets)):
        all_funcs = []
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dvars]
        all_funcs.extend(dvars)
        contract_vars = [v[-1] for v in vars]
        contract_structs = [s[0] for s in structs]
        contract_vars.extend(contract_structs)

        recieve_names = ["recieve", "take", "burn", "allowance", "balance", "point"]
        unallowed = ["stake", "unstake"]
        for var in recieve_names:
            for j in range(len(all_funcs)):
                if var in all_funcs[j][1]:
                    if any(k in all_funcs[j][1] for k in unallowed):
                        continue
                    reqs = extract_requirements([all_funcs[j][4]])[0]
                    vars_to_check = ['allowance', 'balance', 'point']
                    for vc in vars_to_check:
                        if vc not in contract_vars:
                            continue
                        flag = not any(vc in r for r in reqs)
                        if flag:
                            alerts.append({
                                'code': 5,
                                'message': f"Alert, variable '{vc}' is unchecked in function '{all_funcs[j][1]}' in contract '{all_funcs[j][0]}'"
                            })
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='5', legacy_code=5, slug='local_points',
    title='Local Incentive Accounting', category='ComputationAndEconomics',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Confirm that earning and spending paths validate the tracked balance or allowance state.',
)


def run(context):
    alerts = local_points(context.rets)
    return make_findings(alerts, context.normalized_model, **_META)

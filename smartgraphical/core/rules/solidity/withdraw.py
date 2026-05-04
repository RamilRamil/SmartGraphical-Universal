"""Task 9: withdraw_check - checks before withdraw/transfer calls."""
import re
from copy import deepcopy

from smartgraphical.adapters.solidity.helpers import (
    extract_requirements,
    extract_exceptions,
)
from smartgraphical.core.engine import make_findings


def withdraw_check(rets, reader):
    """Task 9 - check guards before withdraw/unstake/transfer calls."""
    alerts = []
    all_funcs = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dvars]
        all_funcs.extend(dvars)

    withdraw_names = ["withdraw", "unstake", "transfer"]
    systematic_functions = ['Transfer', 'Approval', 'revert', 's_feeManager', 'verify']
    wh_funcs = list(set(
        all_funcs[i][1]
        for var in withdraw_names
        for i in range(len(all_funcs))
        if var in all_funcs[i][1]
    ))

    for var in wh_funcs:
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            if var + '(' in f_body:
                var_inds = [m.start() for m in re.finditer(var, f_body)]
                line_indics = []
                for k, vind in enumerate(var_inds):
                    bol = None
                    for j in range(vind, 0, -1):
                        if f_body[j] == ";":
                            bol = j + 1
                            break
                    if bol is None:
                        bol = 1
                    eol = None
                    for j in range(vind, len(f_body)):
                        if f_body[j] == ";":
                            eol = j
                            break
                    if eol is None:
                        eol = len(f_body) - 1
                    temp = f_body[bol:eol + 1]
                    line_indics.append([bol, eol])
                    if 'require' in temp:
                        continue
                    temp = temp.replace(reader.line_sep, '').strip()

                    segment = f_body[:bol] if k == 0 else f_body[line_indics[-2][1]:bol]

                    reqs = extract_requirements([segment])[0]
                    if len(reqs) > 0:
                        alerts.append({'code': 9, 'message': f"Alert: requirements: {reqs}"})
                    conditionals = reader.extract_func_conditionals([segment])[0]
                    if len(conditionals) > 0:
                        alerts.append({'code': 9, 'message': f"Alert: conditionals: {conditionals}"})
                    exp = extract_exceptions(segment)
                    if len(exp) > 0:
                        alerts.append({'code': 9, 'message': f"Alert: Exceptions: {exp}"})
                    for sf in systematic_functions:
                        if sf in segment:
                            alerts.append({'code': 9, 'message': f"Function {sf} is before current line."})
    return alerts


def _withdraw_check_from_normalized(context):
    """Normalized-first withdraw precondition checks (Phase 3)."""
    alerts = []
    model = context.normalized_model
    transfer_tokens = ['withdraw', 'unstake', 'transfer']
    for type_entry in model.types:
        for function in type_entry.functions:
            transfer_statements = []
            for statement in function.transfers:
                if any(token in statement for token in transfer_tokens):
                    transfer_statements.append(statement)
            if not transfer_statements:
                continue
            has_guards = bool(function.guard_facts or function.guards)
            if has_guards:
                continue
            alerts.append({
                'code': 9,
                'message': (
                    f"Alert: no explicit guards before withdraw-like operation in "
                    f"{type_entry.name}.{function.name}, line: {transfer_statements[0]}"
                ),
            })
    return alerts


# ---------------------------------------------------------------------------
# Rule contract (Phase 2)
# ---------------------------------------------------------------------------

_META = dict(
    task_id='9', legacy_code=9, slug='withdraw_check',
    title='Withdraw Preconditions', category='FlowAndOrdering',
    portability='portable_with_adapter', confidence='medium',
    remediation_hint='Ensure withdraw-style operations are preceded by guards, conditions, or validated system checks.',
)


def run(context):
    alerts = _withdraw_check_from_normalized(context)
    return make_findings(alerts, context.normalized_model, **_META)

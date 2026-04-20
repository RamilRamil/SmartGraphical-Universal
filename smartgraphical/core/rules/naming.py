"""Task 1: contract version comments. Task 11: similar names."""
import difflib

from smartgraphical.adapters.solidity.helpers import extract_comment_lines


def contract_version(ln, line_sep):
    """Task 1 - detect version-related keywords in comments."""
    alerts = []
    comments = extract_comment_lines(ln, line_sep)
    var_list = [" version ", " new ", " old "]
    for comment in comments:
        for kw in var_list:
            if kw in comment:
                com = comment.replace(line_sep, ' ')
                alerts.append({
                    'code': 1,
                    'message': f"Alert: keyword '{kw}' used in comment '{com}'"
                })
    return alerts


def similar_names(rets):
    """Task 11 - detect suspiciously similar function/variable names."""
    from copy import deepcopy
    alerts = []
    for i in range(len(rets)):
        all_funcs = []
        all_vars = []
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dfuncs = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dfuncs]
        all_funcs.extend(dfuncs)
        dvars = deepcopy(vars)
        x = [item.insert(0, contract_name) for item in dvars]
        all_vars.extend(dvars)

        for fi, func1 in enumerate(all_funcs):
            for fj, func2 in enumerate(all_funcs[fi + 1:]):
                name = func1[1]
                name2 = func2[1]
                ratio = difflib.SequenceMatcher(None, name, name2).ratio()
                if ratio > 0.9:
                    if (len(name) - len(name2)) / max(len(name), len(name2)) < 0.2:
                        alerts.append({
                            'code': 11,
                            'message': f"Alert: similar function names, function '{name}' in contract '{func1[0]}' and function '{name2}' in contract '{func2[0]}'"
                        })

        for vi, var1 in enumerate(all_vars):
            for vj, var2 in enumerate(all_vars[vi + 1:]):
                name = var1[-1]
                name2 = var2[-1]
                ratio = difflib.SequenceMatcher(None, name, name2).ratio()
                if ratio > 0.9:
                    if (len(name) - len(name2)) / max(len(name), len(name2)) < 0.2:
                        alerts.append({
                            'code': 11,
                            'message': f"Alert: similar variable names, variable '{name}' in contract '{var1[0]}' and variable '{name2}' in contract '{var2[0]}'"
                        })
    return alerts

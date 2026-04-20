"""Task 8: check_order - rebase/fetch must precede transfer."""
import re
from copy import deepcopy


def check_order(rets, reader):
    """Task 8 - verify that rebase/fetch calls appear before transfer/withdraw calls."""
    alerts = []
    all_funcs = []
    for i in range(len(rets)):
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = rets[i]
        dvars = deepcopy(funcs)
        x = [item.insert(0, contract_name) for item in dvars]
        all_funcs.extend(dvars)

    fetch_names = ['rebase']
    transfer_names = ['transfer', 'withdraw', 'unstake']
    fh_funcs = list(set(
        all_funcs[i][1]
        for var in fetch_names
        for i in range(len(all_funcs))
        if var in all_funcs[i][1]
    ))
    tf_funcs = list(set(
        all_funcs[i][1]
        for var in transfer_names
        for i in range(len(all_funcs))
        if var in all_funcs[i][1]
    ))

    for var in tf_funcs:
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            if var in f_body:
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
                    if k == 0:
                        used_flag = any(fh in [f_body[:bol]] for fh in fh_funcs)
                        if not used_flag:
                            alerts.append({
                                'code': 8,
                                'message': f"Alert1: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                            })
                    else:
                        prev_eol = line_indics[-2][1]
                        used_flag = any(fh in [f_body[prev_eol:bol]] for fh in fh_funcs)
                        if not used_flag:
                            alerts.append({
                                'code': 8,
                                'message': f"Alert2: fetch function did not occur before transfer in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                            })

    for var in fh_funcs:
        for i in range(len(all_funcs)):
            f_body = all_funcs[i][4]
            if var in f_body:
                var_inds = [m.start() for m in re.finditer(var, f_body)]
                for k, vind in enumerate(var_inds):
                    bol = None
                    for j in range(vind, 0, -1):
                        if f_body[j] == ";":
                            bol = j + 1
                            break
                    if bol is None:
                        bol = 1
                    eol = None
                    eol2 = None
                    for j in range(vind, len(f_body)):
                        if f_body[j] == ";":
                            eol = j
                            break
                    if eol is None:
                        eol = len(f_body) - 1
                    else:
                        for j in range(eol, len(f_body)):
                            if f_body[j] == ";":
                                eol2 = j
                                break
                    if eol2 is None:
                        eol2 = len(f_body) - 1
                    temp = f_body[bol:eol + 1]
                    if 'require' in temp:
                        continue
                    temp = temp.replace(reader.line_sep, '').strip()
                    used_flag = any(fh in [f_body[eol:]] for fh in tf_funcs)
                    if not used_flag:
                        alerts.append({
                            'code': 8,
                            'message': f"Alert3: transfer function did not occur after fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                        })
                    used_flag = any(fh in [f_body[:eol2 + 1]] for fh in tf_funcs)
                    if not used_flag:
                        alerts.append({
                            'code': 8,
                            'message': f"Alert4: transfer function did not occur in next line of fetch in '{all_funcs[i][1]}' function, '{all_funcs[i][0]}' contract"
                        })
    return alerts

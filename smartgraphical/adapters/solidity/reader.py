import re
from copy import deepcopy

from .helpers import comment_remover, remove_extra_spaces


class ContractReader:
    def __init__(self):
        self.lines = None
        self.line_sep = '--.--'
        self.vars = ['string', 'uint', 'mapping', 'address', 'bytes']
        self.systemic_funcs = [
            'Transfer', 'Approval', 'revert', 'assert', 'abi.decode',
            'abi.encode', 'abi.encodeWithSelector', 'abi.encodeWithSignature',
            'abi.encodePacked', 'abi.encodeCall',
            'data.writeUint32LE', 'data.writeUint64LE', 'readInt8', 'readInt16LE',
            'writeString', 'writeAddress', 'writeUint256LE', 'writeUint64LE',
            'writeInt256LE', 'readAddress', 'writeInt8', 'writeInt32LE',
            'addmod', 'mulmod', '.s_feeManager', '.verify',
        ]
        self.contracts_mem = {}

    def read_file(self, name):
        with open(name) as f:
            lines = f.readlines()
        self.lines = lines
        return lines

    def unify_text(self, lines):
        nc_lines = []
        for i in range(len(lines)):
            if lines[i].strip()[:2] == "//":
                continue
            if "//" in lines[i]:
                ind = lines[i].index('//')
                temp = lines[i][:ind]
                if temp[-5:] == "http:" or temp[-6:] == "https:":
                    nc_lines.append(lines[i].replace('\n', ' '))
                    continue
                nc_lines.append(temp.replace('\n', ' '))
                continue
            nc_lines.append(lines[i].replace('\n', ' '))
        t = ' ' + self.line_sep
        all_code = t.join(nc_lines)
        all_code = comment_remover(all_code)
        all_code = remove_extra_spaces(all_code)
        return all_code

    def extract_func(self, inp):
        brack_iter = 0
        e_ind = None
        if '{' in inp:
            s_ind = inp.index('{')
            for i in range(s_ind + 1, len(inp)):
                if inp[i] == "{":
                    brack_iter += 1
                if inp[i] == "}":
                    brack_iter -= 1
                if brack_iter == -1:
                    e_ind = i
                    break
        else:
            e_ind = inp.index(';')
        return inp[:e_ind + 1]

    def extract_tuple(self, inp):
        s_ind = inp.index('(')
        e_ind = inp.index(')')
        inp = inp[s_ind + 1:e_ind].strip()
        inp_params = inp.split(',')
        inp_params = [i.strip() for i in inp_params]
        ret = [i.split(' ') for i in inp_params]
        return ret

    def extract_fparams(self, inp):
        inp = inp.replace(self.line_sep, '')
        inp = ' '.join(inp.split())
        if '{' in inp:
            ind = inp.index("{")
            inp = inp[:ind]
        else:
            ind = inp.index(";")
            inp = inp[:ind]
        if '(' not in inp:
            name = inp[:]
            name = name.replace('function', '').strip()
            name = name.replace('modifier', '').strip()
            return name, [], []
        s_ind = inp.index('(')
        e_ind = inp.index(')')
        name = inp[:s_ind]
        name = name.replace('function', '').strip()
        name = name.replace('modifier', '').strip()
        inp_params = inp[s_ind:e_ind + 1].strip()
        input_details = self.extract_tuple(inp_params)
        rind = len(inp)
        if 'returns' in inp:
            rind = inp.index('returns')
            ret = inp[rind:]
            ret = ret.replace('returns', '').strip()
            ret_params = self.extract_tuple(ret)
        ext_params = inp[e_ind + 1:rind]
        ext_params = ext_params.strip().split(' ')
        return name, input_details, ext_params

    def extract_body(self, inp):
        inp = inp.replace(self.line_sep, '')
        inp = ' '.join(inp.split())
        assembs = self.extract_assembly(inp)
        for i in assembs:
            inp = inp.replace(i, ' ')
        if '{' in inp:
            ind = inp.index("{")
            inp = inp[ind:]
            ret_str = ''
            if 'return ' in inp or 'return(' in inp:
                rind = inp.index('return')
                ret_str = inp[rind:]
                sem_ind = ret_str.index(';')
                ret_str = ret_str[:sem_ind]
                ret_str = ret_str.replace('return', '').strip()
        else:
            inp = ''
            ret_str = ''
        return inp, ret_str

    def extract_contract(self, inp):
        var_inds = [m.start() for m in re.finditer(self.line_sep + 'contract ', inp)]
        contracts = []
        for j in range(len(var_inds)):
            if inp[var_inds[j]:var_inds[j] + 9] == 'contracts':
                continue
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind + 1]
            contracts.append(f)
        return contracts

    def extract_contract_name(self, inp):
        ind = inp.index('contract ')
        brack_ind = inp.index('{')
        cont_inp = inp[ind:brack_ind]
        cont_inp = cont_inp.replace('contract', '').strip()
        props = []
        if ' is' in cont_inp:
            temp = cont_inp.split(' is')
            temp = [i.strip() for i in temp]
            contract_name = temp[0]
            contract_props = temp[1].split(',')
            contract_props = [i.strip() for i in contract_props]
            props = contract_props
        else:
            contract_name = cont_inp
        return contract_name, props

    def extract_variables(self, inp, gvars, obj_vars):
        ret = []
        d_inp = deepcopy(inp)
        prev_vars = []
        for k in range(len(gvars)):
            t = self.line_sep + ' ' + gvars[k]
            var_inds = [m.start() for m in re.finditer(t, d_inp)]
            for i in range(len(var_inds)):
                eol = None
                for j in range(var_inds[i], len(d_inp)):
                    if d_inp[j] == ";":
                        eol = j
                        break
                temp = d_inp[var_inds[i]:eol + 1]
                repeat_flag = False
                for kk in prev_vars:
                    if temp in kk:
                        repeat_flag = True
                if repeat_flag:
                    continue
                prev_vars.append(deepcopy(temp))
                temp = temp.replace(self.line_sep, '').strip()
                temp = temp.replace(';', '').strip()
                if '=' in temp:
                    ind = temp.index('=')
                    if temp[ind:ind + 2] != '=>':
                        temp = temp[:ind]
                temp = temp.split(' ')
                temp2 = [i for i in temp if i != '']
                ret.append(temp2)
        objs = []
        for k in range(len(obj_vars)):
            t = self.line_sep + ' ' + obj_vars[k]
            var_inds = [m.start() for m in re.finditer(t, inp)]
            for i in range(len(var_inds)):
                eol = None
                for j in range(var_inds[i], len(inp)):
                    if inp[j] == ";":
                        eol = j
                        break
                temp = inp[var_inds[i]:eol + 1]
                temp = temp.replace(self.line_sep, '').strip()
                temp = temp.replace(';', '').strip()
                if '=' in temp:
                    ind = temp.index('=')
                    if temp[ind:ind + 2] != '=>':
                        temp = temp[:ind]
                temp = temp.split(' ')
                temp2 = [i for i in temp if i != '']
                objs.append(temp2)
        return ret, objs

    def extract_structs(self, inp):
        s_inds = [m.start() for m in re.finditer('struct ', inp)]
        ret = []
        for i in range(len(s_inds)):
            brack_iter = 0
            start_flag = 0
            start_ind = 0
            e_ind = None
            temp = inp[s_inds[i]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    start_ind = i
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind + 1]
            f = f.replace(self.line_sep, '')
            name = f[:start_ind].replace('struct', '').strip()
            body = f[start_ind:]
            ret.append([name, body])
        return ret

    def extract_imports(self, inp):
        t = self.line_sep + 'import'
        var_inds = [m.start() for m in re.finditer(t, inp)]
        ret = []
        for i in range(len(var_inds)):
            eol = None
            for j in range(var_inds[i], len(inp)):
                if inp[j] == ";":
                    eol = j
                    break
            temp = inp[var_inds[i]:eol + 1]
            temp = temp.replace(self.line_sep, '').strip()
            temp = temp.replace('import', '')
            temp = temp.replace(';', '').strip()
            ret.append(temp)
        return ret

    def extract_cunstructor(self, inp):
        ind = [m.start() for m in re.finditer('constructor', inp)]
        if len(ind) == 0:
            return ''
        ind = ind[0]
        inp = inp[ind:]
        brack_iter = 0
        e_ind = None
        s_ind = inp.index('{')
        for i in range(s_ind + 1, len(inp)):
            if inp[i] == "{":
                brack_iter += 1
            if inp[i] == "}":
                brack_iter -= 1
            if brack_iter == -1:
                e_ind = i
                break
        f = inp[:e_ind + 1]
        name, input_details, ext_params = self.extract_fparams(f)
        inp, ret_str = self.extract_body(f)
        return f

    def extract_func_conditionals(self, bodies):
        ret = []
        for i in range(len(bodies)):
            var_inds = [m.start() for m in re.finditer(' if', bodies[i])]
            ret_temp = []
            for k in range(len(var_inds)):
                eol = None
                par_iter = 0
                par_ind = bodies[i][var_inds[k]:].index('(')
                for j in range(var_inds[k] + par_ind + 1, len(bodies[i])):
                    if bodies[i][j] == ")":
                        par_iter -= 1
                    if bodies[i][j] == "(":
                        par_iter += 1
                    if par_iter == -1:
                        eol = j
                        break
                temp = bodies[i][var_inds[k]:eol + 1]
                ret_temp.append(temp)
            ret.append(ret_temp)
        return ret

    def extract_var_func_mapping(self, vars, func_names, bodies):
        ret = {}
        for i in vars:
            ret[i] = []
        for i in range(len(vars)):
            for j in range(len(bodies)):
                if vars[i] in bodies[j]:
                    var_inds = [m.start() for m in re.finditer(vars[i], bodies[j])]
                    for k in range(len(var_inds)):
                        if var_inds[k] > 0:
                            if bodies[j][var_inds[k] - 1] == '_':
                                continue
                        if bodies[j][var_inds[k] + len(vars[i])] == '(':
                            continue
                        if not (bodies[j][var_inds[k] + len(vars[i])] == " " or
                                bodies[j][var_inds[k] + len(vars[i])] == "=" or
                                bodies[j][var_inds[k] + len(vars[i])] == "[" or
                                bodies[j][var_inds[k] + len(vars[i])] == ";"):
                            continue
                        if ret[vars[i]].count(func_names[j]) == 0:
                            ret[vars[i]].append(func_names[j])
        return ret

    def extract_func_func_mapping(self, func_names, bodies):
        ret = {}
        for i in func_names:
            ret[i] = []
        for i in range(len(func_names)):
            for j in range(len(bodies)):
                if func_names[i] + '(' in bodies[j] and not '_' + func_names[i] in bodies[j]:
                    if i == j:
                        ret[func_names[i]].append('super.' + func_names[j])
                    else:
                        if ret[func_names[i]].count(func_names[j]) == 0:
                            ret[func_names[i]].append(func_names[j])
        return ret

    def extract_intra_func_func_mapping(self, func_names_parent, func_names, bodies):
        ret = {}
        for i in func_names_parent:
            ret[i] = []
        for i in range(len(func_names_parent)):
            for j in range(len(bodies)):
                if func_names_parent[i] + '(' in bodies[j] and not '_' + func_names_parent[i] in bodies[j]:
                    if ret[func_names_parent[i]].count(func_names[j]) == 0:
                        ret[func_names_parent[i]].append(func_names[j])
        return ret

    def extract_sysfunc_func_mapping(self, func_names, bodies):
        ret = {}
        for i in self.systemic_funcs:
            ret[i] = []
        for i in range(len(self.systemic_funcs)):
            for j in range(len(bodies)):
                if self.systemic_funcs[i] + '(' in bodies[j] and not '_' + self.systemic_funcs[i] in bodies[j]:
                    if ret[self.systemic_funcs[i]].count(func_names[j]) == 0:
                        ret[self.systemic_funcs[i]].append(func_names[j])
        return ret

    def extract_using(self, cont_code):
        ret = []
        if 'using' in cont_code:
            ind = cont_code.index('using')
            temp = cont_code[ind:]
            eol = temp.index(';')
            temp = temp[:eol + 1]
            r = temp.split(' ')
            ret.append(r)
        return ret

    def extract_interface(self, inp):
        var_inds = [m.start() for m in re.finditer('interface ', inp)]
        interfaces = []
        for j in range(len(var_inds)):
            if inp[var_inds[j]:var_inds[j] + 10] == 'interfaces':
                continue
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind + 1]
            f = f.replace(self.line_sep, '')
            interfaces.append(f)
        return interfaces

    def extract_events(self, inp):
        s_inds = [m.start() for m in re.finditer('event ', inp)]
        ret = []
        details = []
        for i in range(len(s_inds)):
            e_ind = None
            temp = inp[s_inds[i]:]
            s_ind = temp.index('(')
            for i in range(s_ind, len(temp)):
                if temp[i] == ";":
                    e_ind = i
                    break
            f = temp[:e_ind + 1]
            name = f[:s_ind].replace('event', '').strip()
            params = f[s_ind:]
            details.append([name, params])
            ret.append(f)
        return ret, details

    def extract_obj_func_mapping(self, objs, func_names, bodies):
        ret = {}
        for i in objs:
            ret[i] = []
        for i in range(len(objs)):
            for j in range(len(bodies)):
                if objs[i] in bodies[j]:
                    var_inds = [m.start() for m in re.finditer(objs[i], bodies[j])]
                    for k in range(len(var_inds)):
                        if var_inds[k] > 0:
                            if bodies[j][var_inds[k] - 1] == '_':
                                continue
                        if bodies[j][var_inds[k] + len(objs[i])] == '(':
                            continue
                        if not (bodies[j][var_inds[k] + len(objs[i])] == "."):
                            continue
                        e_ind = bodies[j][var_inds[k]:].index('(')
                        obj_func_name = bodies[j][var_inds[k] + len(objs[i]) + 1: var_inds[k] + e_ind]
                        if ret[objs[i]].count([func_names[j], obj_func_name]) == 0:
                            ret[objs[i]].append([func_names[j], obj_func_name])
        return ret

    def extract_assembly(self, inp):
        var_inds = [m.start() for m in re.finditer('assembly ', inp)]
        assembs = []
        for j in range(len(var_inds)):
            brack_iter = 0
            start_flag = 0
            e_ind = None
            temp = inp[var_inds[j]:]
            s_ind = temp.index('{')
            for i in range(s_ind, len(temp)):
                if temp[i] == "{":
                    brack_iter += 1
                    start_flag = 1
                    continue
                if temp[i] == "}":
                    brack_iter -= 1
                if brack_iter == 0 and start_flag:
                    e_ind = i
                    break
            f = temp[:e_ind + 1]
            assembs.append(f)
        return assembs

    def __call__(self, all_code):
        analyzed_contracts = []
        contracts = self.extract_contract(all_code)
        interfaces = self.extract_interface(all_code)
        interf = [i.replace('interface', 'contract') for i in interfaces]
        contracts.extend(interf)
        ret = []
        hierarchy = {}
        for i in range(len(contracts)):
            funcs = []
            cont_code = contracts[i]
            using = self.extract_using(cont_code)
            structs = self.extract_structs(cont_code)
            func_inds = [m.start() for m in re.finditer('function ', cont_code)]
            modif_inds = [m.start() for m in re.finditer('modifier ', cont_code)]
            func_inds.extend(modif_inds)
            res_code = deepcopy(cont_code)
            for i in range(len(func_inds)):
                f = self.extract_func(cont_code[func_inds[i]:])
                res_code = res_code.replace(f, ' ')
                name, input_details, ext_params = self.extract_fparams(f)
                body, ret_str = self.extract_body(f)
                funcs.append([name, input_details, ext_params, body])
            contract_name, parents = self.extract_contract_name(cont_code)
            hierarchy[contract_name] = parents
            self.contracts_mem[contract_name] = {}
            self.contracts_mem[contract_name]['funcs'] = deepcopy(funcs)
            f = self.extract_cunstructor(cont_code)
            if len(f) > 0:
                res_code = res_code.replace(f, ' ')
                name, input_details, ext_params = self.extract_fparams(f)
                body, ret_str = self.extract_body(f)
                constructor = [name, input_details, ext_params, body]
            else:
                constructor = []
            events, evt_details = self.extract_events(res_code)
            for ev in events:
                res_code = res_code.replace(ev, ' ')
            vars, objs = self.extract_variables(res_code, self.vars, analyzed_contracts)
            imps = self.extract_imports(res_code)
            var_names = [i[-1] for i in vars]
            var_names.extend([i[0] for i in structs])
            func_names = [i[0] for i in funcs]
            func_bodies = [i[3] for i in funcs]
            if len(constructor) == 1:
                func_names.extend([constructor[0]])
                func_bodies.extend([constructor[-1]])
            for dt in evt_details:
                func_names.append(dt[0])
                func_bodies.append('')
            var_func_mapping = self.extract_var_func_mapping(var_names, func_names, func_bodies)
            func_func_mapping = self.extract_func_func_mapping(func_names, func_bodies)
            sysfunc_func_mapping = self.extract_sysfunc_func_mapping(func_names, func_bodies)
            obj_names = [i[-1] for i in objs]
            obj_func_mapping = self.extract_obj_func_mapping(obj_names, func_names, func_bodies)
            func_conditionals = self.extract_func_conditionals(func_bodies)
            analyzed_contracts.append(contract_name)
            ret.append([
                contract_name, funcs, vars, structs, imps,
                var_func_mapping, func_func_mapping, sysfunc_func_mapping,
                obj_func_mapping, func_conditionals, constructor, evt_details, objs, using,
            ])
        all_contract_names = list(hierarchy.keys())
        high_connections = []
        for k, v in hierarchy.items():
            if len(v) == 0:
                continue
            for j in range(len(v)):
                parent_cont = v[j]
                child_cont = k
                if parent_cont not in all_contract_names:
                    continue
                parent_ind = all_contract_names.index(parent_cont)
                child_ind = all_contract_names.index(child_cont)
                var_temp = ret[parent_ind][2]
                vars = [k[-1] for k in var_temp]
                func_temp = ret[child_ind][1]
                func_names = [k[0] for k in func_temp]
                func_bodies = [k[3] for k in func_temp]
                var_func_mapping = self.extract_var_func_mapping(vars, func_names, func_bodies)
                func_temp2 = ret[parent_ind][1]
                func_names_parent = [k[0] for k in func_temp2]
                func_func_mapping = self.extract_intra_func_func_mapping(func_names_parent, func_names, func_bodies)
                conn = {
                    'parent': parent_cont, 'child': child_cont,
                    'var_func_mapping': var_func_mapping,
                    'func_func_mapping': func_func_mapping,
                }
                high_connections.append(conn)
        int_len = len(interfaces)
        scaned_int = ret[-int_len:] if int_len > 0 else []
        for i in range(len(contracts)):
            for j in range(len(scaned_int)):
                if scaned_int[j][0] in contracts[i]:
                    parent_cont = scaned_int[j][0]
                    child_cont = ret[i][0]
                    if parent_cont not in all_contract_names:
                        continue
                    parent_ind = all_contract_names.index(parent_cont)
                    child_ind = all_contract_names.index(child_cont)
                    var_temp = ret[parent_ind][2]
                    vars = [k[-1] for k in var_temp]
                    func_temp = ret[child_ind][1]
                    func_names = [k[0] for k in func_temp]
                    func_bodies = [k[3] for k in func_temp]
                    var_func_mapping = self.extract_var_func_mapping(vars, func_names, func_bodies)
                    func_temp2 = ret[parent_ind][1]
                    func_names_parent = [k[0] for k in func_temp2]
                    func_func_mapping = self.extract_intra_func_func_mapping(
                        func_names_parent, func_names, func_bodies
                    )
                    conn = {
                        'parent': parent_cont, 'child': child_cont,
                        'var_func_mapping': var_func_mapping,
                        'func_func_mapping': func_func_mapping,
                    }
                    high_connections.append(conn)
        return ret, hierarchy, high_connections

import re
import difflib


def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " "
        return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE,
    )
    return re.sub(pattern, replacer, text)


def remove_extra_spaces(inp):
    return ' '.join(inp.split())


def similar_string(target_string, string_list):
    closest_match = difflib.get_close_matches(target_string, string_list, n=1, cutoff=0.6)
    return closest_match[0] if closest_match else None


def extract_requirements(bodies):
    ret = []
    for i in range(len(bodies)):
        var_inds = [m.start() for m in re.finditer('require', bodies[i])]
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
            if bodies[i][eol + 1] == ';':
                eol += 1
            ret_temp.append(bodies[i][var_inds[k]:eol + 1])
        ret.append(ret_temp)
    return ret


def extract_exceptions(f_body):
    var_inds = [m.start() for m in re.finditer('try', f_body)]
    try_catches = []
    for k in range(len(var_inds)):
        temp = []
        for j in range(len(f_body)):
            eol = None
            par_iter = 0
            par_ind = f_body[var_inds[k]:].index('{')
            for j in range(var_inds[k] + par_ind + 1, len(f_body)):
                if f_body[j] == "}":
                    par_iter -= 1
                if f_body[j] == "{":
                    par_iter += 1
                if par_iter == -1:
                    eol = j
                    break
        temp.append(f_body[var_inds[k]:eol + 1])
        rest = f_body[eol + 1:].strip()
        if rest[:len('catch')] == 'catch':
            for j in range(len(rest)):
                eol2 = None
                par_iter = 0
                par_ind = rest.index('{')
                for j in range(par_ind + 1, len(rest)):
                    if rest[j] == "}":
                        par_iter -= 1
                    if rest[j] == "{":
                        par_iter += 1
                    if par_iter == -1:
                        eol2 = j
                        break
            temp.append(rest[:eol2 + 1])
        try_catches.append(temp)
    return try_catches


def extract_asserts(bodies):
    ret = []
    for i in range(len(bodies)):
        var_inds = [m.start() for m in re.finditer('assert', bodies[i])]
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
            if bodies[i][eol + 1] == ';':
                eol += 1
            ret_temp.append(bodies[i][var_inds[k]:eol + 1])
        ret.append(ret_temp)
    return ret


def extract_operation(var, body):
    ret = []
    var_inds = [m.start() for m in re.finditer(var, body)]
    for i in range(len(var_inds)):
        bol = None
        for j in range(var_inds[i], 0, -1):
            if body[j] == ";":
                bol = j
                break
        eol = None
        for j in range(var_inds[i], len(body)):
            if body[j] == ";":
                eol = j
                break
        temp = body[bol:eol + 1]
        ret.append(temp[1:])
    return ret


def find_uniques(inp):
    unique = []
    for item in inp:
        if item not in unique:
            unique.append(item)
    return unique


def extract_comment_lines(lines, line_sep):
    all_comments = []
    nc_lines = []
    for line in lines:
        if line.strip()[:2] == "//":
            all_comments.append(line)
            continue
        if "//" in line:
            ind = line.index('//')
            temp = line[:ind]
            if temp[-5:] == "http:" or temp[-6:] == "https:":
                nc_lines.append(line.replace('\n', ' '))
                continue
            nc_lines.append(temp.replace('\n', ' '))
            continue
        nc_lines.append(line.replace('\n', ' '))
    t = ' ' + line_sep
    all_code = t.join(nc_lines)

    def replacer(match):
        s = match.group(0)
        all_comments.append(s)
        if s.startswith('/'):
            return " "
        return s

    pattern = re.compile(r'/\*.*?\*/', re.DOTALL | re.MULTILINE)
    re.sub(pattern, replacer, all_code)
    return all_comments


def intra_contract_connection(high_connections, func_name):
    for connection in high_connections:
        maps = connection['func_func_mapping']
        for k, v in maps.items():
            if func_name in v:
                return True
    return False

"""Solidity adapter: parses .sol files and builds the registry of rule runners."""
import re
from copy import deepcopy

from smartgraphical.core.engine import RuleSpec
from smartgraphical.core.model import (
    AdapterBlueprint,
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedCustomError,
    NormalizedEvent,
    NormalizedExternalCall,
    NormalizedFunction,
    NormalizedGuardFact,
    NormalizedStateAccess,
    NormalizedObjectUse,
    NormalizedStateEntity,
    NormalizedType,
)
from smartgraphical.adapters.solidity.reader import ContractReader
from smartgraphical.adapters.solidity import state_access
from smartgraphical.adapters.solidity.import_resolve import collect_lines_with_imports
from smartgraphical.adapters.solidity.helpers import (
    extract_requirements,
    extract_asserts,
)

# Rule runner imports (Phase 2: no legacy dependency)
from smartgraphical.core.rules.solidity.naming import run_contract_version, run_similar_names
from smartgraphical.core.rules.portable.tainted_input_unguarded_sink import run as run_tainted_input
from smartgraphical.core.rules.solidity.state_mutation import (
    run_unallowed_manipulation,
    run_pool_interactions,
)
from smartgraphical.core.rules.solidity.staking import run as run_staking
from smartgraphical.core.rules.solidity.access_control import run as run_local_points
from smartgraphical.core.rules.solidity.error_handling import run as run_exceptions
from smartgraphical.core.rules.solidity.computation import run as run_complicated_calculations
from smartgraphical.core.rules.solidity.ordering import run as run_check_order
from smartgraphical.core.rules.solidity.withdraw import run as run_withdraw_check
from smartgraphical.core.rules.solidity.outer_calls import run as run_outer_calls
from smartgraphical.core.rules.solidity.min_slippage_bounds import (
    run as run_min_slippage_bounds,
)
from smartgraphical.core.rules.solidity.knowdit_reentrancy import (
    run_bridge_retry_gap,
    run_read_only_oracle_gap,
    run_unstake_share_order,
)


TASK_GROUPS = {
    'NamingAndConsistency': ['1', '10'],
    'StateAndMutation': ['2', '4', '11'],
    'FlowAndOrdering': ['6', '8', '9'],
    'ComputationAndEconomics': ['3', '5', '7', '12'],
    'AdvancedReentrancy': ['13', '14', '15'],
    'VisualizationOnly': [],
}

SECOND_LANGUAGE_POC = AdapterBlueprint(
    target_language='rust_or_cpp',
    required_entities=['FunctionLike', 'StateEntity', 'CallSite', 'Guard', 'Mutation'],
    portable_rule_tasks=['3', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15'],
    success_criteria=[
        'Extract the normalized entities for one non-trivial source file.',
        'Run at least two portable rules on the normalized model.',
        'Render the same overview graph from the normalized model.',
    ],
)


def build_rule_registry():
    """Build registry where every runner accepts (context) -> list[Finding]."""
    return {
        '1':  RuleSpec('1',  1,  'contract_version',        'Old Version Markers',         'NamingAndConsistency',    'portable',             'low',    'Review rewrite markers and keep comments aligned with the current implementation.',                               run_contract_version),
        '2':  RuleSpec('2',  2,  'unallowed_manipulation',  'External State Manipulation', 'StateAndMutation',        'portable_with_adapter', 'medium', 'Check assignments sourced from inputs or external values before they update sensitive state.',                   run_unallowed_manipulation),
        '3':  RuleSpec('3',  3,  'staking',                 'Stake And Release Logic',     'ComputationAndEconomics', 'portable_with_adapter', 'medium', 'Verify that stake and release paths are symmetric and guard the manipulated amount.',                           run_staking),
        '4':  RuleSpec('4',  4,  'pool_interactions',       'Pool Supply Operations',      'StateAndMutation',        'portable_with_adapter', 'medium', 'Review mint or burn style flows for missing access control and accounting assumptions.',                        run_pool_interactions),
        '5':  RuleSpec('5',  5,  'local_points',            'Local Incentive Accounting',  'ComputationAndEconomics', 'portable_with_adapter', 'medium', 'Confirm that earning and spending paths validate the tracked balance or allowance state.',                      run_local_points),
        '6':  RuleSpec('6',  6,  'exceptions',              'Error Path Consistency',      'FlowAndOrdering',         'portable_with_adapter', 'medium', 'Inspect try/catch handlers and ensure the error path preserves valid state transitions.',                       run_exceptions),
        '7':  RuleSpec('7',  7,  'complicated_calculations','Complicated Calculations',    'ComputationAndEconomics', 'portable_with_adapter', 'medium', 'Review arithmetic-heavy expressions and simplify or guard the most complex branches.',                         run_complicated_calculations),
        '8':  RuleSpec('8',  8,  'check_order',             'Sensitive Call Ordering',     'FlowAndOrdering',         'portable_with_adapter', 'medium', 'Check whether fetch, price, or preparation logic happens immediately before transfer-like effects.',             run_check_order),
        '9':  RuleSpec('9',  9,  'withdraw_check',          'Withdraw Preconditions',      'FlowAndOrdering',         'portable_with_adapter', 'medium', 'Ensure withdraw-style operations are preceded by guards, conditions, or validated system checks.',              run_withdraw_check),
        '10': RuleSpec('10', 10, 'similar_names',           'Similar Names',               'NamingAndConsistency',    'portable',              'medium', 'Rename near-duplicate identifiers when they can confuse reviewers or callers.',                                 run_similar_names),
        '11': RuleSpec('11', 11, 'outer_calls',             'Outer Calls',                 'StateAndMutation',        'portable_with_adapter', 'medium', 'Review public entrypoints that consume inputs and mutate state without stronger constraints.',                  run_outer_calls),
        '12': RuleSpec('12', 12, 'min_slippage_bounds',    'Minimum Bounds On Swap And Liquidity Calls', 'ComputationAndEconomics', 'portable_with_adapter', 'medium', 'Replace zero literals for min-amount, min-shares, and deadline parameters with user-supplied or quote-derived bounds.', run_min_slippage_bounds),
        '13': RuleSpec('13', 13, 'read_only_oracle_reentrancy', 'Read-Only Reentrancy Window (Reserve Valuation)', 'AdvancedReentrancy', 'portable_with_adapter', 'medium', 'Finalize reserves or sync before external calls when pricing depends on reserves.', run_read_only_oracle_gap),
        '14': RuleSpec('14', 14, 'bridge_retry_reentrancy', 'Bridge Retry Idempotency Ordering', 'AdvancedReentrancy', 'portable_with_adapter', 'medium', 'Consume or finalize retry/relay records before payouts or other external effects.', run_bridge_retry_gap),
        '15': RuleSpec('15', 15, 'unstake_share_burn_order', 'Unstake Share Burn Ordering', 'AdvancedReentrancy', 'portable_with_adapter', 'medium', 'Reduce or burn staking shares before paying out rewards or principal.', run_unstake_share_order),
        '16': RuleSpec('16', 16, 'tainted_input_unguarded_sink', 'Untrusted input reaches a sensitive sink without a guard', 'dataflow', 'portable', 'medium', 'Validate or guard untrusted input before it reaches the sink (heuristic intra-procedural taint).', run_tainted_input),
    }


# ---------------------------------------------------------------------------
# Normalized model builder
# ---------------------------------------------------------------------------

def _normalize_statement(statement):
    return statement.replace('\n', ' ').replace('\t', ' ').strip()


def _split_body(body):
    return [_normalize_statement(p) for p in body.split(';') if _normalize_statement(p)]


def _collect_guards(body, conditionals):
    guards = list(conditionals)
    for req in extract_requirements([body])[0]:
        if req not in guards:
            guards.append(req)
    for assertion in extract_asserts([body])[0]:
        if assertion not in guards:
            guards.append(assertion)
    return guards


def _collect_guard_facts(body, conditionals):
    facts = []
    for conditional in conditionals:
        facts.append(NormalizedGuardFact(
            guard_type='conditional',
            expression=conditional,
            source_statement=conditional,
            confidence_reason='parsed_function_conditional',
        ))
    for req in extract_requirements([body])[0]:
        facts.append(NormalizedGuardFact(
            guard_type='require',
            expression=req,
            source_statement=req,
            confidence_reason='parsed_require_statement',
        ))
    for assertion in extract_asserts([body])[0]:
        facts.append(NormalizedGuardFact(
            guard_type='assert',
            expression=assertion,
            source_statement=assertion,
            confidence_reason='parsed_assert_statement',
        ))
    return facts


def _collect_state_accesses(body, state_names, modifiers=None):
    reads, writes, mutations = state_access.collect_function_state_accesses(
        body,
        state_names,
        modifiers or [],
    )
    return reads, writes, mutations


def _append_state_access_edges(model, source_type, type_entry):
    state_names = [e.name for e in type_entry.state_entities]
    for function in type_entry.functions:
        for access in function.read_accesses or []:
            model.call_edges.append(NormalizedCallEdge(
                source_type,
                access.entity_name,
                source_type,
                function.name,
                'state_to_function_read',
            ))
        _reads, write_accesses, _mutations = state_access.collect_function_state_accesses(
            function.body,
            state_names,
            function.modifiers,
        )
        for access in write_accesses:
            model.call_edges.append(NormalizedCallEdge(
                source_type,
                access.entity_name,
                source_type,
                function.name,
                'state_to_function_write',
            ))


def _collect_transfers(body):
    tokens = ['.transfer(', ' transfer(', '.send(', '.call{value:', 'withdraw(', 'unstake(']
    result = []
    for stmt in _split_body(body):
        if any(t in stmt for t in tokens) and stmt not in result:
            result.append(stmt)
    return result


def _collect_external_calls(body, object_calls, system_calls):
    calls = []
    external_tokens = ['.call(', '.call{', '.delegatecall(', '.staticcall(', '.send(', '.transfer(']
    for stmt in _split_body(body):
        if any(token in stmt for token in external_tokens):
            calls.append(NormalizedExternalCall(
                call_kind='value_or_low_level',
                target_name='unknown',
                source_statement=stmt,
                via_object='',
            ))
    for object_call in object_calls:
        calls.append(NormalizedExternalCall(
            call_kind='object_method',
            target_name=object_call.get('label', ''),
            source_statement='',
            via_object=object_call.get('object', ''),
        ))
    for system_call in system_calls:
        calls.append(NormalizedExternalCall(
            call_kind='system_call',
            target_name=system_call,
            source_statement='',
            via_object='',
        ))
    return calls


def _collect_computations(body):
    tokens = ['.mul', '.div', '.add', '.sub', 'math.', '+', '-', '*', '/']
    result = []
    for stmt in _split_body(body):
        if sum(1 for t in tokens if t in stmt) >= 2 and stmt not in result:
            result.append(stmt)
    return result


_SOLIDITY_SIGNATURE_MODIFIERS = frozenset({
    "public", "external", "internal", "private",
    "pure", "view", "payable", "constant",
    "virtual", "override",
})


def _sanitize_function_ext_params(func_name, ext_params):
    """Drop parent constructor initializers mistaken for modifier tokens."""
    tokens = list(ext_params or [])
    if func_name != "constructor":
        return tokens
    cleaned = []
    for token in tokens:
        t = (token or "").strip()
        if not t or t == "__declared_modifier__":
            continue
        if "(" in t or ")" in t:
            continue
        if t in _SOLIDITY_SIGNATURE_MODIFIERS:
            cleaned.append(t)
    return cleaned


def _extract_visibility(ext_params):
    visibilities = ['public', 'external', 'internal', 'private']
    for value in ext_params:
        if value in visibilities:
            return value
    return ''


def _extract_permissions(ext_params):
    permissions = []
    for value in ext_params:
        lowered = value.lower()
        if ('only' in lowered) or ('owner' in lowered) or ('admin' in lowered) or ('role' in lowered):
            if value not in permissions:
                permissions.append(value)
    return permissions


def _extract_param_names(input_details):
    names = []
    for index, item in enumerate(input_details):
        if not item:
            names.append(f"arg{index}")
            continue
        candidate = str(item[-1]).strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
            names.append(candidate)
        else:
            names.append(f"arg{index}")
    return names


def _split_arguments(raw_args):
    parts = []
    current = []
    paren_depth = 0
    square_depth = 0
    curly_depth = 0
    for ch in raw_args:
        if ch == "," and paren_depth == 0 and square_depth == 0 and curly_depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)
        if ch == "(":
            paren_depth += 1
        elif ch == ")" and paren_depth > 0:
            paren_depth -= 1
        elif ch == "[":
            square_depth += 1
        elif ch == "]" and square_depth > 0:
            square_depth -= 1
        elif ch == "{":
            curly_depth += 1
        elif ch == "}" and curly_depth > 0:
            curly_depth -= 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_callsites(body, callee_name):
    sites = []
    pattern = re.compile(rf"\b(?:super\.)?{re.escape(callee_name)}\s*\(")
    for match in pattern.finditer(body):
        start = match.start()
        open_idx = body.find("(", match.end() - 1)
        if open_idx < 0:
            continue
        depth = 0
        close_idx = -1
        for idx in range(open_idx, len(body)):
            ch = body[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = idx
                    break
        if close_idx < 0:
            continue
        sites.append(body[start:close_idx + 1].strip())
    return sites


def _line_numbers_for_callsites(lines, callsites):
    if not lines or not callsites:
        return []
    matched = set()
    for number, line in enumerate(lines, start=1):
        source_line = line.strip()
        if not source_line:
            continue
        for callsite in callsites:
            if callsite and callsite in source_line:
                matched.add(number)
                break
    return sorted(matched)


def _is_literal_value(value):
    token = (value or "").strip()
    if not token:
        return False
    if token in {"true", "false"}:
        return True
    if token.startswith(("'", '"')):
        return True
    if re.fullmatch(r"\d+", token):
        return True
    if re.fullmatch(r"0x[0-9a-fA-F]+", token):
        return True
    if token.startswith(("address(", "uint", "int", "bytes", "string(")):
        return True
    return False


def _contains_identifier(value, identifier):
    if not value or not identifier:
        return False
    pattern = rf"\b{re.escape(identifier)}\b"
    return re.search(pattern, value) is not None


def _arg_source_kind(arg_value, caller_params, state_names):
    value = (arg_value or "").strip()
    if not value:
        return "unknown"
    if _is_literal_value(value):
        return "literal"
    for param in caller_params:
        if _contains_identifier(value, param):
            return "input"
    for state_name in state_names:
        if _contains_identifier(value, state_name):
            return "state"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[[^\]]+\])?", value):
        return "local"
    return "unknown"


def _call_metadata_for_target(
    body,
    callee_name,
    callee_params,
    source_lines,
    caller_params=None,
    state_names=None,
):
    caller_params = caller_params or []
    state_names = state_names or []
    callsites = _extract_callsites(body, callee_name)
    if not callsites:
        return {"callsite": "", "args_map": [], "line_numbers": []}
    callsite = callsites[0]
    open_idx = callsite.find("(")
    close_idx = callsite.rfind(")")
    args_raw = callsite[open_idx + 1:close_idx] if open_idx >= 0 and close_idx > open_idx else ""
    args = _split_arguments(args_raw)
    args_map = []
    for index, value in enumerate(args):
        param_name = callee_params[index] if index < len(callee_params) else f"arg{index}"
        args_map.append({
            "param": param_name,
            "value": value,
            "source_kind": _arg_source_kind(value, caller_params, state_names),
        })
    return {
        "callsite": callsite,
        "args_map": args_map,
        "line_numbers": _line_numbers_for_callsites(source_lines, callsites),
    }


def _render_full_function_source(func_name, input_details, ext_params, body):
    params = ", ".join(" ".join(p).strip() for p in (input_details or []) if p)
    normalized_ext = [p for p in (ext_params or []) if p and p != "__declared_modifier__"]
    visibility_tokens = []
    returns_tokens = []
    other_tokens = []
    for token in normalized_ext:
        lowered = token.lower()
        if lowered in {"public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override"}:
            visibility_tokens.append(token)
        elif lowered.startswith("returns"):
            returns_tokens.append(token)
        else:
            other_tokens.append(token)

    header = f"function {func_name}({params})"
    if visibility_tokens:
        header = f"{header}\n    {' '.join(visibility_tokens)}"
    if other_tokens:
        header = f"{header}\n    {' '.join(other_tokens)}"
    if returns_tokens:
        header = f"{header}\n    {' '.join(returns_tokens)}"

    normalized_body = (body or "").strip()
    if not normalized_body:
        return f"{header};"
    if normalized_body.startswith("{") and normalized_body.endswith("}"):
        inner = normalized_body[1:-1].strip()
        if inner:
            statement_lines = [s.strip() for s in inner.split(";") if s.strip()]
            pretty_inner = "\n".join(f"    {line};" for line in statement_lines)
            return f"{header} {{\n{pretty_inner}\n}}"
        return f"{header} {{\n}}"
    return f"{header}\n{normalized_body}"


def _emit_event_edges(contract_name, funcs, event_names):
    """Wire bidirectional emit(...) in function bodies to declared events.

    Event names are appended to func_names in ContractReader only so that
    variable-to-function reachability can see events; they must not produce
    bogus function_to_function rows (event as caller). Those are skipped when
    building call_edges; this helper adds the correct function_to_event edges.
    """
    edges = []
    if not event_names:
        return edges
    for func in funcs:
        func_name, _inputs, _ext, body = func
        for ev in event_names:
            if re.search(r'\bemit\s+%s\s*\(' % re.escape(ev), body):
                edges.append(NormalizedCallEdge(
                    contract_name, func_name, contract_name, ev, 'function_to_event',
                ))
    return edges


def _emit_custom_error_edges(contract_name, funcs, error_names):
    """Link functions that `revert ErrorName(...)` to declared custom errors."""

    edges = []
    if not error_names:
        return edges
    for func in funcs:
        func_name, _inputs, _ext, body = func
        body = body or ""
        if not body.strip():
            continue
        for en in error_names:
            if not en:
                continue
            esc = re.escape(en)
            patterns = [r'\brevert\s+%s\s*\(' % esc]
            if '.' not in en:
                patterns.append(r'\brevert\s+[\w.]+\.%s\s*\(' % esc)
            if any(re.search(p, body) for p in patterns):
                edges.append(NormalizedCallEdge(
                    contract_name, func_name, contract_name, en, 'function_to_custom_error',
                ))
    return edges


def _parse_import_symbol_entries(imps):
    entries = []
    for imp_str in imps or []:
        imp_name, imp_path = _extract_import_name(imp_str)
        brace = re.search(r"\{([^}]+)\}", imp_str)
        if brace:
            for part in brace.group(1).split(","):
                sym = part.strip()
                if sym:
                    entries.append((sym, imp_path))
        elif imp_name:
            entries.append((imp_name, imp_path))
    return entries


def _function_line_numbers_for_symbol(file_lines, full_source, symbol):
    if not file_lines or not full_source:
        return []
    if not re.search(rf"\b{re.escape(symbol)}\b", full_source):
        return []
    matched = []
    for num, line in enumerate(file_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("import "):
            continue
        if re.search(rf"\b{re.escape(symbol)}\b", line):
            matched.append(num)
    return matched


def _callsite_for_symbol_lines(file_lines, line_numbers, symbol):
    for num in line_numbers or []:
        if 0 < num <= len(file_lines):
            line = file_lines[num - 1]
            if re.search(rf"\b{re.escape(symbol)}\b", line):
                return line.strip()
    return ""


def _append_import_usage_edges(model, contract_name, imps, functions, file_lines):
    entries = _parse_import_symbol_entries(imps)
    used_symbols = set()
    for fn in functions:
        full = getattr(fn, "full_source", "") or getattr(fn, "body", "") or ""
        func_name = getattr(fn, "name", "") or ""
        if not full or not func_name:
            continue
        for sym, path in entries:
            if not re.search(rf"\b{re.escape(sym)}\b", full):
                continue
            line_nums = _function_line_numbers_for_symbol(file_lines, full, sym)
            if not line_nums:
                continue
            used_symbols.add(sym)
            model.call_edges.append(NormalizedCallEdge(
                contract_name,
                func_name,
                sym,
                sym,
                "import_dependency",
                label=path,
                callsite=_callsite_for_symbol_lines(file_lines, line_nums, sym),
                line_numbers=line_nums,
                import_symbol=sym,
            ))
    for sym, path in entries:
        if sym in used_symbols:
            continue
        model.call_edges.append(NormalizedCallEdge(
            contract_name,
            contract_name,
            sym,
            sym,
            "import_dependency",
            label=path,
            import_symbol=sym,
        ))


def _append_constructor_parent_edges(
    model,
    contract_name,
    constructor,
    parents,
    file_lines,
    contracts_in_file,
):
    if not constructor or len(constructor) < 4 or not parents:
        return
    in_file = set(contracts_in_file or [])
    cname, input_details, ext_params, body = constructor[:4]
    full_ctor = _render_full_function_source(cname, input_details, ext_params, body)
    for parent in parents:
        if not parent or parent == contract_name:
            continue
        if parent not in in_file:
            continue
        if not re.search(rf"\b{re.escape(parent)}\s*\(", full_ctor):
            continue
        meta = _call_metadata_for_target(full_ctor, parent, [], file_lines)
        line_nums = meta.get("line_numbers") or []
        if not line_nums:
            line_nums = _function_line_numbers_for_symbol(file_lines, full_ctor, parent)
        model.call_edges.append(NormalizedCallEdge(
            contract_name,
            "constructor",
            parent,
            "constructor",
            "cross_type_call",
            label=f"{parent}()",
            callsite=meta.get("callsite") or _callsite_for_symbol_lines(file_lines, line_nums, parent),
            line_numbers=line_nums,
        ))


def _extract_import_name(import_str):
    """Parse a raw Solidity import string into (short_name, full_path).

    Handles plain paths and named imports:
      '"./Token.sol"'                         -> ('Token', './Token.sol')
      '{ IERC20 } from "@oz/.../IERC20.sol"'  -> ('IERC20', '@oz/.../IERC20.sol')
      '* as Utils from "./Utils.sol"'         -> ('Utils', './Utils.sol')
    """
    s = import_str.strip()
    if ' from ' in s:
        s = s.split(' from ', 1)[-1].strip()
    s = s.strip('"').strip("'")
    full_path = s
    basename = s.rsplit('/', 1)[-1] if '/' in s else s
    short_name = basename.rsplit('.', 1)[0] if '.' in basename else basename
    return short_name, full_path


def build_normalized_model(context):
    artifact = NormalizedArtifact(context.path, context.language, 'SolidityAdapterV0')
    model = NormalizedAuditModel(
        artifact=artifact,
        rule_groups=deepcopy(TASK_GROUPS),
        second_language_poc=deepcopy(SECOND_LANGUAGE_POC),
    )
    unit_kinds = getattr(context, 'solidity_unit_kinds', None) or {}
    contracts_in_file = [row[0] for row in context.rets]
    for contract_data in context.rets:
        (contract_name, funcs, vars, structs, imps,
         var_func_mapping, func_func_mapping, sysfunc_func_mapping,
         obj_func_mapping, func_conditionals, constructor, events, custom_errors, objs, using) = contract_data

        sk = (unit_kinds.get(contract_name) or 'concrete').strip().lower()
        if sk not in ('concrete', 'abstract', 'interface', 'library'):
            sk = 'concrete'
        type_entry = NormalizedType(
            contract_name,
            'contract_like',
            parents=context.hierarchy.get(contract_name, []),
            is_abstract=(sk == 'abstract'),
            solidity_unit_kind=sk,
        )

        for variable in vars:
            type_entry.state_entities.append(NormalizedStateEntity(variable[-1], contract_name, 'state_variable', ' '.join(variable)))
        for struct in structs:
            type_entry.state_entities.append(NormalizedStateEntity(struct[0], contract_name, 'struct', struct[1]))
        for obj in objs:
            type_entry.objects.append(NormalizedObjectUse(obj[-1], obj[0], ''))
            type_entry.state_entities.append(NormalizedStateEntity(obj[-1], contract_name, 'object_instance', ' '.join(obj)))

        state_names = [e.name for e in type_entry.state_entities]
        func_items = list(funcs)
        if constructor and len(constructor) >= 4:
            func_items.append(constructor)
        function_bodies = {}
        function_param_names = {}
        for idx, func in enumerate(func_items):
            func_name, input_details, ext_params, body = func
            ext_params = _sanitize_function_ext_params(func_name, ext_params)
            function_bodies[func_name] = body
            function_param_names[func_name] = _extract_param_names(input_details)
            conditionals = func_conditionals[idx] if idx < len(func_conditionals) else []
            system_calls = [s for s, users in sysfunc_func_mapping.items() if func_name in users]
            object_calls = [
                {'object': obj_name, 'label': m[1]}
                for obj_name, mappings in obj_func_mapping.items()
                for m in mappings if m[0] == func_name
            ]
            split_statements = _split_body(body)
            guard_facts = _collect_guard_facts(body, conditionals)
            guards = _collect_guards(body, conditionals)
            read_accesses, mutation_accesses, mutations = _collect_state_accesses(
                body, state_names, ext_params,
            )
            visibility = _extract_visibility(ext_params)
            permissions = _extract_permissions(ext_params)
            external_calls = _collect_external_calls(body, object_calls, system_calls)
            evidence_map = []
            for mutation in mutations:
                evidence_map.append({
                    'type_name': contract_name,
                    'function_name': func_name,
                    'source_statement': mutation,
                    'confidence_reason': 'mutation_detected_from_state_assignment',
                })
            for guard_fact in guard_facts:
                evidence_map.append({
                    'type_name': contract_name,
                    'function_name': func_name,
                    'source_statement': guard_fact.source_statement,
                    'confidence_reason': guard_fact.confidence_reason,
                })
            type_entry.functions.append(NormalizedFunction(
                name=func_name, owner=contract_name, inputs=input_details,
                modifiers=ext_params, body=body, conditionals=conditionals,
                full_source=_render_full_function_source(func_name, input_details, ext_params, body),
                guards=guards,
                guard_facts=guard_facts,
                internal_calls=deepcopy(func_func_mapping.get(func_name, [])),
                system_calls=system_calls, object_calls=object_calls,
                mutations=mutations,
                read_accesses=read_accesses,
                transfers=_collect_transfers(body),
                external_calls=external_calls,
                computations=_collect_computations(body),
                is_entrypoint=('external' in ext_params or 'public' in ext_params),
                visibility=visibility,
                entrypoint_permissions=permissions,
                findings_evidence_map=evidence_map,
                exploration_statements=split_statements,
            ))
            function_key = f"{contract_name}.{func_name}"
            model.exploration_data.function_notes[function_key] = {
                'statement_count': len(split_statements),
                'raw_statements': split_statements,
            }
            model.findings_data.function_facts[function_key] = {
                'guard_types': [fact.guard_type for fact in guard_facts],
                'entrypoint': ('external' in ext_params or 'public' in ext_params),
                'permissions': permissions,
                'read_access_count': len(read_accesses),
                'mutation_count': len(mutation_accesses),
                'external_call_count': len(external_calls),
            }
            model.findings_data.evidence_index[function_key] = evidence_map

        for event in events:
            type_entry.events.append(NormalizedEvent(event[0], contract_name, event[1]))
        for err in custom_errors:
            type_entry.custom_errors.append(NormalizedCustomError(err[0], contract_name, err[1]))
        model.types.append(type_entry)

        event_name_set = {ev[0] for ev in events}
        error_name_set = {e[0] for e in custom_errors}
        _append_state_access_edges(model, contract_name, type_entry)
        for callee, callers in func_func_mapping.items():
            if callee in event_name_set or callee in error_name_set:
                continue
            for caller in callers:
                is_super = str(caller).startswith("super.")
                resolved_caller = caller.replace("super.", "", 1) if is_super else caller
                metadata_callee = f"super.{callee}" if is_super else callee
                metadata = _call_metadata_for_target(
                    function_bodies.get(resolved_caller, ""),
                    metadata_callee,
                    function_param_names.get(callee, []),
                    context.lines,
                    caller_params=function_param_names.get(resolved_caller, []),
                    state_names=state_names,
                )
                model.call_edges.append(NormalizedCallEdge(
                    contract_name,
                    resolved_caller,
                    contract_name,
                    callee,
                    'function_to_function',
                    callsite=metadata["callsite"],
                    args_map=metadata["args_map"],
                    line_numbers=metadata["line_numbers"],
                ))
        for edge in _emit_event_edges(contract_name, funcs, list(event_name_set)):
            model.call_edges.append(edge)
        for edge in _emit_custom_error_edges(contract_name, funcs, list(error_name_set)):
            model.call_edges.append(edge)
        for sys_name, users in sysfunc_func_mapping.items():
            for fn in users:
                model.call_edges.append(NormalizedCallEdge(contract_name, fn, contract_name, sys_name, 'function_to_system'))
        obj_to_type = {obj[-1]: obj[0] for obj in objs}
        for obj_name, mappings in obj_func_mapping.items():
            for m in mappings:
                model.call_edges.append(NormalizedCallEdge(contract_name, m[0], contract_name, obj_name, 'function_to_object', m[1]))
                target_type = obj_to_type.get(obj_name, '')
                if target_type:
                    model.call_edges.append(NormalizedCallEdge(
                        contract_name, m[0],
                        target_type, m[1],
                        'cross_contract_call',
                        label=f"{obj_name}.{m[1]}",
                    ))

        _append_import_usage_edges(
            model,
            contract_name,
            imps,
            type_entry.functions,
            context.lines or [],
        )
        _append_constructor_parent_edges(
            model,
            contract_name,
            constructor,
            context.hierarchy.get(contract_name, []) or [],
            context.lines or [],
            contracts_in_file,
        )

    type_by_name = {t.name: t for t in model.types}
    for conn in context.high_connections:
        parent, child = conn['parent'], conn['child']
        parent_type = type_by_name.get(parent)
        child_type = type_by_name.get(child)
        if not parent_type or not child_type:
            continue
        parent_state_names = {e.name for e in parent_type.state_entities}
        for function in child_type.functions:
            for access in function.read_accesses or []:
                if access.entity_name in parent_state_names:
                    model.call_edges.append(NormalizedCallEdge(
                        parent,
                        access.entity_name,
                        child,
                        function.name,
                        'cross_type_state_read',
                    ))
            _reads, write_accesses, _mutations = state_access.collect_function_state_accesses(
                function.body,
                [e.name for e in child_type.state_entities],
                function.modifiers,
            )
            for access in write_accesses:
                if access.entity_name in parent_state_names:
                    model.call_edges.append(NormalizedCallEdge(
                        parent,
                        access.entity_name,
                        child,
                        function.name,
                        'cross_type_state_write',
                    ))
        for callee, callers in conn['func_func_mapping'].items():
            for caller in callers:
                model.call_edges.append(NormalizedCallEdge(
                    child,
                    caller,
                    parent,
                    callee,
                    'cross_type_call',
                ))
    return model


# ---------------------------------------------------------------------------
# Adapter class
# ---------------------------------------------------------------------------

class SolidityAdapterV0:
    def __init__(self):
        self.reader = ContractReader()

    def parse_source(self, source_path, *, expand_local_imports=True):
        """Parse one Solidity source file.

        When ``expand_local_imports`` is True (default), relative ``.sol`` imports
        beside the file are merged in (single-file upload). Bundle scans pass
        False so each member is analyzed once without duplicating siblings.
        """
        if expand_local_imports:
            lines = collect_lines_with_imports(
                source_path,
                self.reader.read_file,
            )
        else:
            lines = self.reader.read_file(source_path)
        self.reader.lines = lines
        unified_source = self.reader.unify_text(lines)
        parsed_rets, parsed_hierarchy, parsed_high_connections, parsed_unit_kinds = self.reader(unified_source)
        context = AnalysisContext(
            path=source_path,
            language='solidity',
            reader=self.reader,
            lines=lines,
            unified_code=unified_source,
            rets=parsed_rets,
            hierarchy=parsed_hierarchy,
            high_connections=parsed_high_connections,
            solidity_unit_kinds=parsed_unit_kinds,
        )
        context.normalized_model = build_normalized_model(context)
        return context

"""
SmartGraphical - compatibility layer.
All logic lives in smartgraphical.* packages; this module re-exports
the symbols needed for backward compatibility and acts as the legacy CLI entry point.
"""
import sys
from copy import deepcopy

try:
    import graphviz
except ImportError:
    graphviz = None

# ---------------------------------------------------------------------------
# Imports from new modules (re-exported for legacy.* access via adapter.py)
# ---------------------------------------------------------------------------
from smartgraphical.adapters.solidity.helpers import (
    comment_remover,
    remove_extra_spaces,
    similar_string,
    extract_requirements,
    extract_exceptions,
    extract_asserts,
    extract_operation,
    find_uniques,
    extract_comment_lines,
    intra_contract_connection,
)
from smartgraphical.adapters.solidity.reader import ContractReader
from smartgraphical.core.model import (
    NormalizedArtifact,
    NormalizedStateEntity,
    NormalizedEvent,
    NormalizedObjectUse,
    NormalizedFunction,
    NormalizedType,
    NormalizedCallEdge,
    AdapterBlueprint,
    NormalizedAuditModel,
    AnalysisContext,
)
from smartgraphical.core.findings import FindingEvidence, Finding
from smartgraphical.core.engine import (
    RuleSpec,
    infer_evidence_from_message,
    convert_alerts_to_findings,
    summarize_model,
    demonstrate_findings,
)
from smartgraphical.core.graph import GraphBuilder, sanitize_graph_token

from smartgraphical.core.rules.naming import (
    contract_version as _rule_contract_version,
    similar_names as _rule_similar_names,
)
from smartgraphical.core.rules.state_mutation import (
    unallowed_manipulation as _rule_unallowed_manipulation,
    pool_interactions as _rule_pool_interactions,
)
from smartgraphical.core.rules.staking import staking as _rule_staking
from smartgraphical.core.rules.access_control import local_points as _rule_local_points
from smartgraphical.core.rules.error_handling import exceptions as _rule_exceptions
from smartgraphical.core.rules.computation import (
    complicated_calculations as _rule_complicated_calculations,
)
from smartgraphical.core.rules.ordering import check_order as _rule_check_order
from smartgraphical.core.rules.withdraw import withdraw_check as _rule_withdraw_check
from smartgraphical.core.rules.outer_calls import outer_calls as _rule_outer_calls

# ---------------------------------------------------------------------------
# Legacy global state (set by bind_runtime_context / bind_legacy_runtime)
# ---------------------------------------------------------------------------
filename = ''
task = ''
ln = []
unified_code = ''
rets = []
hierarchy = {}
high_connections = []
reader = None
analysis_context = None

# ---------------------------------------------------------------------------
# Thin wrapper helpers
# ---------------------------------------------------------------------------

def demonstrate_alerts(alerts):
    for alert in alerts:
        print(alert)
        print("\n    ----------------------      \n")


def comment_extractor(lines):
    return extract_comment_lines(lines, reader.line_sep)


# ---------------------------------------------------------------------------
# Thin wrapper rule functions (no-arg, use globals)
# ---------------------------------------------------------------------------

def contract_version():
    return _rule_contract_version(ln, reader.line_sep)


def unallowed_manipulation():
    return _rule_unallowed_manipulation(rets, reader)


def staking():
    return _rule_staking(rets)


def pool_interactions():
    return _rule_pool_interactions(rets)


def local_points():
    return _rule_local_points(rets)


def exceptions():
    return _rule_exceptions(rets)


def complicated_calculations():
    return _rule_complicated_calculations(rets, reader)


def check_order():
    return _rule_check_order(rets, reader)


def withdraw_check():
    return _rule_withdraw_check(rets, reader)


def similar_names():
    return _rule_similar_names(rets)


def outer_calls():
    return _rule_outer_calls(rets, reader, high_connections)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TASK_GROUPS = {
    'NamingAndConsistency': ['1', '10'],
    'StateAndMutation': ['2', '4', '11'],
    'FlowAndOrdering': ['6', '8', '9'],
    'ComputationAndEconomics': ['3', '5', '7'],
    'VisualizationOnly': ['12'],
}

SECOND_LANGUAGE_POC = AdapterBlueprint(
    target_language='rust_or_cpp',
    required_entities=['FunctionLike', 'StateEntity', 'CallSite', 'Guard', 'Mutation'],
    portable_rule_tasks=['3', '6', '7', '8', '9', '10', '11'],
    success_criteria=[
        'Extract the normalized entities for one non-trivial source file.',
        'Run at least two portable rules on the normalized model.',
        'Render the same overview graph from the normalized model.',
    ],
)


def build_rule_registry():
    return {
        '1':  RuleSpec('1',  1,  'contract_version',        'Old Version Markers',          'NamingAndConsistency',     'portable',             'low',    'Review rewrite markers and keep comments aligned with the current implementation.',                                contract_version),
        '2':  RuleSpec('2',  2,  'unallowed_manipulation',  'External State Manipulation',  'StateAndMutation',         'portable_with_adapter', 'medium', 'Check assignments sourced from inputs or external values before they update sensitive state.',                    unallowed_manipulation),
        '3':  RuleSpec('3',  3,  'staking',                 'Stake And Release Logic',      'ComputationAndEconomics',  'portable_with_adapter', 'medium', 'Verify that stake and release paths are symmetric and guard the manipulated amount.',                            staking),
        '4':  RuleSpec('4',  4,  'pool_interactions',       'Pool Supply Operations',       'StateAndMutation',         'portable_with_adapter', 'medium', 'Review mint or burn style flows for missing access control and accounting assumptions.',                         pool_interactions),
        '5':  RuleSpec('5',  5,  'local_points',            'Local Incentive Accounting',   'ComputationAndEconomics',  'portable_with_adapter', 'medium', 'Confirm that earning and spending paths validate the tracked balance or allowance state.',                       local_points),
        '6':  RuleSpec('6',  6,  'exceptions',              'Error Path Consistency',       'FlowAndOrdering',          'portable_with_adapter', 'medium', 'Inspect try/catch handlers and ensure the error path preserves valid state transitions.',                        exceptions),
        '7':  RuleSpec('7',  7,  'complicated_calculations','Complicated Calculations',     'ComputationAndEconomics',  'portable_with_adapter', 'medium', 'Review arithmetic-heavy expressions and simplify or guard the most complex branches.',                          complicated_calculations),
        '8':  RuleSpec('8',  8,  'check_order',             'Sensitive Call Ordering',      'FlowAndOrdering',          'portable_with_adapter', 'medium', 'Check whether fetch, price, or preparation logic happens immediately before transfer-like effects.',              check_order),
        '9':  RuleSpec('9',  9,  'withdraw_check',          'Withdraw Preconditions',       'FlowAndOrdering',          'portable_with_adapter', 'medium', 'Ensure withdraw-style operations are preceded by guards, conditions, or validated system checks.',               withdraw_check),
        '10': RuleSpec('10', 11, 'similar_names',           'Similar Names',                'NamingAndConsistency',     'portable',              'medium', 'Rename near-duplicate identifiers when they can confuse reviewers or callers.',                                  similar_names),
        '11': RuleSpec('11', 12, 'outer_calls',             'Outer Calls',                  'StateAndMutation',         'portable_with_adapter', 'medium', 'Review public entrypoints that consume inputs and mutate state without stronger constraints.',                   outer_calls),
    }


# ---------------------------------------------------------------------------
# Normalize helpers (used by adapter.py via legacy.*)
# ---------------------------------------------------------------------------

def normalize_statement(statement):
    return statement.replace('\n', ' ').replace('\t', ' ').strip()


def split_body_statements(body):
    return [normalize_statement(part) for part in body.split(';') if normalize_statement(part)]


def collect_function_guards(body, conditionals):
    guards = []
    for conditional in conditionals:
        if conditional not in guards:
            guards.append(conditional)
    for requirement in extract_requirements([body])[0]:
        if requirement not in guards:
            guards.append(requirement)
    for assertion in extract_asserts([body])[0]:
        if assertion not in guards:
            guards.append(assertion)
    return guards


def collect_mutations(body, state_names):
    mutations = []
    for statement in split_body_statements(body):
        for state_name in state_names:
            if state_name in statement and ('=' in statement or '+=' in statement or '-=' in statement):
                if statement not in mutations:
                    mutations.append(statement)
    return mutations


def collect_transfers(body):
    transfers = []
    transfer_tokens = ['.transfer(', ' transfer(', '.send(', '.call{value:', 'withdraw(', 'unstake(']
    for statement in split_body_statements(body):
        for token in transfer_tokens:
            if token in statement and statement not in transfers:
                transfers.append(statement)
    return transfers


def collect_computations(body):
    computations = []
    operator_tokens = ['.mul', '.div', '.add', '.sub', 'math.', '+', '-', '*', '/']
    for statement in split_body_statements(body):
        hit_count = sum(1 for token in operator_tokens if token in statement)
        if hit_count >= 2 and statement not in computations:
            computations.append(statement)
    return computations


def build_normalized_model(context):
    artifact = NormalizedArtifact(context.path, context.language, 'SolidityAdapterV0')
    model = NormalizedAuditModel(
        artifact=artifact,
        rule_groups=deepcopy(TASK_GROUPS),
        second_language_poc=deepcopy(SECOND_LANGUAGE_POC),
    )
    for contract_data in context.rets:
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = contract_data
        type_entry = NormalizedType(contract_name, 'contract_like', parents=context.hierarchy.get(contract_name, []))
        for variable in vars:
            type_entry.state_entities.append(NormalizedStateEntity(variable[-1], contract_name, 'state_variable', ' '.join(variable)))
        for struct in structs:
            type_entry.state_entities.append(NormalizedStateEntity(struct[0], contract_name, 'struct', struct[1]))
        for obj in objs:
            type_entry.objects.append(NormalizedObjectUse(obj[-1], obj[0], ''))
            type_entry.state_entities.append(NormalizedStateEntity(obj[-1], contract_name, 'object_instance', ' '.join(obj)))
        state_names = [entity.name for entity in type_entry.state_entities]
        for index, func in enumerate(funcs):
            func_name, input_details, ext_params, body = func
            conditionals = func_conditionals[index] if index < len(func_conditionals) else []
            system_calls = [sys_name for sys_name, users in sysfunc_func_mapping.items() if func_name in users]
            object_calls = []
            for object_name, mappings in obj_func_mapping.items():
                for mapping in mappings:
                    if mapping[0] == func_name:
                        object_calls.append({'object': object_name, 'label': mapping[1]})
            normalized_function = NormalizedFunction(
                name=func_name, owner=contract_name, inputs=input_details,
                modifiers=ext_params, body=body, conditionals=conditionals,
                guards=collect_function_guards(body, conditionals),
                internal_calls=deepcopy(func_func_mapping.get(func_name, [])),
                system_calls=system_calls, object_calls=object_calls,
                mutations=collect_mutations(body, state_names),
                transfers=collect_transfers(body),
                computations=collect_computations(body),
                is_entrypoint=('external' in ext_params or 'public' in ext_params),
            )
            type_entry.functions.append(normalized_function)
        for event in events:
            type_entry.events.append(NormalizedEvent(event[0], contract_name, event[1]))
        model.types.append(type_entry)
        for variable_name, used_by in var_func_mapping.items():
            for function_name in used_by:
                model.call_edges.append(NormalizedCallEdge(contract_name, variable_name, contract_name, function_name, 'state_to_function'))
        for source_name, targets in func_func_mapping.items():
            for target_name in targets:
                model.call_edges.append(NormalizedCallEdge(contract_name, source_name, contract_name, target_name.replace('super.', ''), 'function_to_function'))
        for sys_name, users in sysfunc_func_mapping.items():
            for function_name in users:
                model.call_edges.append(NormalizedCallEdge(contract_name, function_name, contract_name, sys_name, 'function_to_system'))
        for object_name, mappings in obj_func_mapping.items():
            for mapping in mappings:
                model.call_edges.append(NormalizedCallEdge(contract_name, mapping[0], contract_name, object_name, 'function_to_object', mapping[1]))
    for connection in context.high_connections:
        parent_name = connection['parent']
        child_name = connection['child']
        for variable_name, used_by in connection['var_func_mapping'].items():
            for function_name in used_by:
                model.call_edges.append(NormalizedCallEdge(parent_name, variable_name, child_name, function_name, 'cross_type_state'))
        for source_name, targets in connection['func_func_mapping'].items():
            for target_name in targets:
                model.call_edges.append(NormalizedCallEdge(parent_name, source_name, child_name, target_name, 'cross_type_call'))
    return model


def bind_runtime_context(context):
    global filename, task, ln, unified_code, rets, hierarchy, high_connections, reader, analysis_context
    filename = context.path
    ln = context.lines
    unified_code = context.unified_code
    rets = context.rets
    hierarchy = context.hierarchy
    high_connections = context.high_connections
    reader = context.reader
    analysis_context = context


# ---------------------------------------------------------------------------
# Application classes (legacy path)
# ---------------------------------------------------------------------------

class SolidityAdapterV0:
    def __init__(self):
        self.reader = ContractReader()

    def parse_source(self, source_path):
        lines = self.reader.read_file(source_path)
        unified_source = self.reader.unify_text(lines)
        parsed_rets, parsed_hierarchy, parsed_high_connections = self.reader(unified_source)
        context = AnalysisContext(
            path=source_path,
            language='solidity',
            reader=self.reader,
            lines=lines,
            unified_code=unified_source,
            rets=parsed_rets,
            hierarchy=parsed_hierarchy,
            high_connections=parsed_high_connections,
        )
        context.normalized_model = build_normalized_model(context)
        bind_runtime_context(context)
        return context


class RuleEngine:
    def __init__(self, rule_registry):
        self.rule_registry = rule_registry

    def run_task(self, context, task_id):
        bind_runtime_context(context)
        rule_spec = self.rule_registry[task_id]
        alerts = rule_spec.runner()
        return convert_alerts_to_findings(rule_spec, alerts, context)

    def run_all(self, context):
        findings = []
        for task_id in sorted(self.rule_registry.keys(), key=int):
            findings.extend(self.run_task(context, task_id))
        return findings


cluster_border_color = "#4D869C"
cluster_background_color = "#F8F6F422"
var_fill_color = "#95D2B380"
func_fill_color = "#D2E9E9"
sysfunc_fill_color = "#E3F4F4"
edge_color = "#D77FA1"


def plot_graph(model):
    GraphBuilder().render(model, filename)


# ---------------------------------------------------------------------------
# CLI constants
# ---------------------------------------------------------------------------

HELP_TEXT = " ------------------------------------------------------------------\n \
   Help:\n \
\n Task 1: The signatures associated with the function definitions in every function of the smart contract code must be examined and updated if the contract is the outcome of a rewrite or update of another contract. If this isn't done, the contract may have a logical issue, and information from the previous signature may be given to the functions using the programmer's imagination. This inevitably indicates that the contract code contains a runtime error.\n \
-----\n\
Task 2: In the event that the developer modifies contract parameters, such as the maximum fee or user balance, or other elements, like totalSupply, that are determined by another contract. This could be risky and result in warnings being generated. Generally speaking, obtaining any value from a source outside the contract may have a different value under various circumstances, which could lead to a smart contract logical error. For instance, the programmer might not have incorporated the input's fluctuation or range into the program logic\n \
-----\n\
Task 3: The quantity of collateral determines one of the typical actions in DeFi smart contracts, in addition to stake and unstake. Attacks like multiple borrowing without collateral might result from logical mistakes made by the developer when releasing this collateral, determining the maximum loan amount that can be given, and determining the kind and duration of the collateral encumbrance\n \
-----\n\
Tasks 3 and 5 and 9: When a smart contract receives value, like financial tokens or game points (from staking assets, depositing points, or depositing tokens), it must perform a logical check when the assets are removed from the system to ensure that no user can circumvent the program's logic and take more money out of the contract than they are actually entitled to. \n \
-----\n\
Tasks 2 and 4: All token supply calculations must be performed accurately and completely. Even system security and authentication might be taken into account, but the communication method specification is entirely incorrect. For instance, one of the several errors made by developers has been the presence of a function like burn that can remove tokens from the pool or functions identical to it that can add tokens to the pool. To determine whether this is necessary in terms of program logic and whether other supply changes are taken into account in this computation, these conditions should be looked at. No specific function is required, and burning tokens can be moved to an address as a transaction without being returned. \n \
-----\n\
Task 2 and 5 and 9: There are various incentive aspects in many smart contracts that defy logic. For instance, if the smart contract has a point system for burning tokens, is it possible to use that point in other areas of the contract? It is crucial to examine the income and spending points in this situation. For instance, the developer can permit spending without making sure the user validates the point earning. The program logic may be abused as a result of this. \n \
-----\n\
Task 6: The code's error conditions need to be carefully examined. For instance, a logical error and a serious blow to the smart contract can result from improperly validating the error circumstances. Assume, for instance, that the programmer uses a system function to carry out a non-deterministic transport, but its error management lacks a proper understanding of the system state. In the event of an error, for instance, the coder attempts to reverse the system state; however, this may not be logically sound and could result in misuse of the smart contract by, for instance, reproducing an unauthorized activity in the normal state. \n \
-----\n\
Task 7: Logical errors can result from any complicated coding calculations. For instance, a cyber attacker may exploit the program logic by forcing their desired computation output if the coder fails to properly analyze the code output under various scenarios. \n \
-----\n\
Tasks 8 and 9: A smart contract's execution output might be impacted by the sequence in which certain procedures are carried out. The developer measuring or calculating the price of a token (or anything similar) and then transferring the asset at a certain time period is one of the most prevalent examples of this kind of vulnerability. Given that the attacker can manipulate the market through fictitious fluctuations, this is a logical issue. Thus, this gives the attacker the ability to remove the asset from the agreement. \n \
-----\n\
Task 10: In a smart contract, using names that are spelled similarly to one another may cause logical issues. For instance, the coder might inadvertently substitute one of these definitions for another in the contract, which would be undetectable during the coder's initial tests. There is a chance that a cybercriminal will take advantage of this scenario. \n \
-----\n\
Task 11: A smart contract's function that can be called fully publicly and without limitations may be risky and necessitate additional research from the developer if it modifies variables, delivers inventory, or does something similar\n \
-------------------------------------------------------------------------------\n\
"

TASK_PROMPT = '\n 1: Old version\n \
2: Unallowed manipulation\n \
3: Stake function\n \
4: Pool interactions\n \
5: Local points\n \
6: Exceptions\n \
7: Complicated calculations\n \
8: Order of calls\n \
9: Withdraw actions\n \
10: Similar names\n \
11: Outer calls\n \
12: Graphical demonstration\n \
13: Run all tasks\n \
Enter task number:  '


def parse_cli_args(argv):
    if len(argv) < 2:
        print("Error: Please provide a Solidity filename as an argument (ex: python SmartGraphical.py contract1.sol)")
        sys.exit(1)
    if not argv[1]:
        print("Error: Filename cannot be empty or None.")
        sys.exit(1)
    selected_task = None
    output_mode = 'legacy'
    if len(argv) >= 3:
        selected_task = argv[2]
    if len(argv) >= 4:
        output_mode = argv[3].lower()
    if output_mode not in ['legacy', 'auditor', 'explore']:
        print("Error: mode must be one of legacy, auditor, or explore.")
        sys.exit(1)
    return argv[1], selected_task, output_mode


def select_task_interactively():
    print(HELP_TEXT)
    selected_task = input(TASK_PROMPT)
    print("task    ", selected_task)
    return selected_task


class SmartGraphicalApplication:
    def __init__(self):
        self.adapter = SolidityAdapterV0()
        self.rule_engine = RuleEngine(build_rule_registry())
        self.graph_builder = GraphBuilder()

    def analyze(self, source_path):
        return self.adapter.parse_source(source_path)

    def execute(self, context, selected_task, output_mode):
        if output_mode == 'explore':
            summarize_model(context)
        if selected_task in self.rule_engine.rule_registry:
            findings = self.rule_engine.run_task(context, selected_task)
            demonstrate_findings(findings, output_mode)
            return
        if selected_task == '12':
            self.graph_builder.render(context.normalized_model, context.path)
            return
        if selected_task == '13':
            findings = self.rule_engine.run_all(context)
            demonstrate_findings(findings, output_mode)
            self.graph_builder.render(context.normalized_model, context.path)
            return
        print("Error: task must be a value from 1 to 13.")
        sys.exit(1)


def main(argv=None):
    if argv is None:
        argv = sys.argv
    source_path, selected_task, output_mode = parse_cli_args(argv)
    application = SmartGraphicalApplication()
    context = application.analyze(source_path)
    if selected_task is None:
        selected_task = select_task_interactively()
    global task
    task = selected_task
    application.execute(context, selected_task, output_mode)


if __name__ == '__main__':
    main()

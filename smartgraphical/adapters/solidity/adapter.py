from copy import deepcopy
import importlib

from smartgraphical.core.engine import RuleSpec
from smartgraphical.core.model import (
    AdapterBlueprint,
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedEvent,
    NormalizedFunction,
    NormalizedObjectUse,
    NormalizedStateEntity,
    NormalizedType,
)


legacy = importlib.import_module("SmartGraphical")


TASK_GROUPS = {
    "NamingAndConsistency": ["1", "10"],
    "StateAndMutation": ["2", "4", "11"],
    "FlowAndOrdering": ["6", "8", "9"],
    "ComputationAndEconomics": ["3", "5", "7"],
    "VisualizationOnly": ["12"],
}


SECOND_LANGUAGE_POC = AdapterBlueprint(
    target_language="rust_or_cpp",
    required_entities=[
        "FunctionLike",
        "StateEntity",
        "CallSite",
        "Guard",
        "Mutation",
    ],
    portable_rule_tasks=["3", "6", "7", "8", "9", "10", "11"],
    success_criteria=[
        "Extract the normalized entities for one non-trivial source file.",
        "Run at least two portable rules on the normalized model.",
        "Render the same overview graph from the normalized model.",
    ],
)


class SolidityAnalysisContext(AnalysisContext):
    def bind_legacy_runtime(self):
        legacy.filename = self.path
        legacy.ln = self.lines
        legacy.unified_code = self.unified_code
        legacy.rets = self.rets
        legacy.hierarchy = self.hierarchy
        legacy.high_connections = self.high_connections
        legacy.reader = self.reader
        legacy.analysis_context = self


def build_rule_registry():
    return {
        "1": RuleSpec("1", 1, "contract_version", "Old Version Markers", "NamingAndConsistency", "portable", "low", "Review rewrite markers and keep comments aligned with the current implementation.", legacy.contract_version),
        "2": RuleSpec("2", 2, "unallowed_manipulation", "External State Manipulation", "StateAndMutation", "portable_with_adapter", "medium", "Check assignments sourced from inputs or external values before they update sensitive state.", legacy.unallowed_manipulation),
        "3": RuleSpec("3", 3, "staking", "Stake And Release Logic", "ComputationAndEconomics", "portable_with_adapter", "medium", "Verify that stake and release paths are symmetric and guard the manipulated amount.", legacy.staking),
        "4": RuleSpec("4", 4, "pool_interactions", "Pool Supply Operations", "StateAndMutation", "portable_with_adapter", "medium", "Review mint or burn style flows for missing access control and accounting assumptions.", legacy.pool_interactions),
        "5": RuleSpec("5", 5, "local_points", "Local Incentive Accounting", "ComputationAndEconomics", "portable_with_adapter", "medium", "Confirm that earning and spending paths validate the tracked balance or allowance state.", legacy.local_points),
        "6": RuleSpec("6", 6, "exceptions", "Error Path Consistency", "FlowAndOrdering", "portable_with_adapter", "medium", "Inspect try/catch handlers and ensure the error path preserves valid state transitions.", legacy.exceptions),
        "7": RuleSpec("7", 7, "complicated_calculations", "Complicated Calculations", "ComputationAndEconomics", "portable_with_adapter", "medium", "Review arithmetic-heavy expressions and simplify or guard the most complex branches.", legacy.complicated_calculations),
        "8": RuleSpec("8", 8, "check_order", "Sensitive Call Ordering", "FlowAndOrdering", "portable_with_adapter", "medium", "Check whether fetch, price, or preparation logic happens immediately before transfer-like effects.", legacy.check_order),
        "9": RuleSpec("9", 9, "withdraw_check", "Withdraw Preconditions", "FlowAndOrdering", "portable_with_adapter", "medium", "Ensure withdraw-style operations are preceded by guards, conditions, or validated system checks.", legacy.withdraw_check),
        "10": RuleSpec("10", 11, "similar_names", "Similar Names", "NamingAndConsistency", "portable", "medium", "Rename near-duplicate identifiers when they can confuse reviewers or callers.", legacy.similar_names),
        "11": RuleSpec("11", 12, "outer_calls", "Outer Calls", "StateAndMutation", "portable_with_adapter", "medium", "Review public entrypoints that consume inputs and mutate state without stronger constraints.", legacy.outer_calls),
    }


def normalize_statement(statement):
    return statement.replace("\n", " ").replace("\t", " ").strip()


def split_body_statements(body):
    return [normalize_statement(part) for part in body.split(";") if normalize_statement(part)]


def collect_function_guards(body, conditionals):
    guards = []
    for conditional in conditionals:
        if conditional not in guards:
            guards.append(conditional)
    for requirement in legacy.extract_requirements([body])[0]:
        if requirement not in guards:
            guards.append(requirement)
    for assertion in legacy.extract_asserts([body])[0]:
        if assertion not in guards:
            guards.append(assertion)
    return guards


def collect_mutations(body, state_names):
    mutations = []
    for statement in split_body_statements(body):
        for state_name in state_names:
            if state_name in statement and ("=" in statement or "+=" in statement or "-=" in statement):
                if statement not in mutations:
                    mutations.append(statement)
    return mutations


def collect_transfers(body):
    transfers = []
    transfer_tokens = [".transfer(", " transfer(", ".send(", ".call{value:", "withdraw(", "unstake("]
    for statement in split_body_statements(body):
        for token in transfer_tokens:
            if token in statement and statement not in transfers:
                transfers.append(statement)
    return transfers


def collect_computations(body):
    computations = []
    operator_tokens = [".mul", ".div", ".add", ".sub", "math.", "+", "-", "*", "/"]
    for statement in split_body_statements(body):
        hit_count = 0
        for token in operator_tokens:
            if token in statement:
                hit_count += 1
        if hit_count >= 2 and statement not in computations:
            computations.append(statement)
    return computations


def build_normalized_model(context):
    artifact = NormalizedArtifact(context.path, context.language, "SolidityAdapterV0")
    model = NormalizedAuditModel(
        artifact=artifact,
        rule_groups=deepcopy(TASK_GROUPS),
        second_language_poc=deepcopy(SECOND_LANGUAGE_POC),
    )

    for contract_data in context.rets:
        contract_name, funcs, vars, structs, imps, var_func_mapping, func_func_mapping, sysfunc_func_mapping, obj_func_mapping, func_conditionals, constructor, events, objs, using = contract_data
        type_entry = NormalizedType(contract_name, "contract_like", parents=context.hierarchy.get(contract_name, []))

        for variable in vars:
            raw_signature = " ".join(variable)
            type_entry.state_entities.append(NormalizedStateEntity(variable[-1], contract_name, "state_variable", raw_signature))
        for struct in structs:
            type_entry.state_entities.append(NormalizedStateEntity(struct[0], contract_name, "struct", struct[1]))
        for obj in objs:
            object_use = NormalizedObjectUse(obj[-1], obj[0], "")
            type_entry.objects.append(object_use)
            type_entry.state_entities.append(NormalizedStateEntity(obj[-1], contract_name, "object_instance", " ".join(obj)))

        state_names = [entity.name for entity in type_entry.state_entities]
        for index, func in enumerate(funcs):
            func_name, input_details, ext_params, body = func
            conditionals = func_conditionals[index] if index < len(func_conditionals) else []
            system_calls = [sys_name for sys_name, users in sysfunc_func_mapping.items() if func_name in users]
            object_calls = []
            for object_name, mappings in obj_func_mapping.items():
                for mapping in mappings:
                    if mapping[0] == func_name:
                        object_calls.append({"object": object_name, "label": mapping[1]})

            normalized_function = NormalizedFunction(
                name=func_name,
                owner=contract_name,
                inputs=input_details,
                modifiers=ext_params,
                body=body,
                conditionals=conditionals,
                guards=collect_function_guards(body, conditionals),
                internal_calls=deepcopy(func_func_mapping.get(func_name, [])),
                system_calls=system_calls,
                object_calls=object_calls,
                mutations=collect_mutations(body, state_names),
                transfers=collect_transfers(body),
                computations=collect_computations(body),
                is_entrypoint=("external" in ext_params or "public" in ext_params),
            )
            type_entry.functions.append(normalized_function)

        for event in events:
            type_entry.events.append(NormalizedEvent(event[0], contract_name, event[1]))

        model.types.append(type_entry)

        for variable_name, used_by in var_func_mapping.items():
            for function_name in used_by:
                model.call_edges.append(NormalizedCallEdge(contract_name, variable_name, contract_name, function_name, "state_to_function"))
        for source_name, targets in func_func_mapping.items():
            for target_name in targets:
                clean_target = target_name.replace("super.", "")
                model.call_edges.append(NormalizedCallEdge(contract_name, source_name, contract_name, clean_target, "function_to_function"))
        for sys_name, users in sysfunc_func_mapping.items():
            for function_name in users:
                model.call_edges.append(NormalizedCallEdge(contract_name, function_name, contract_name, sys_name, "function_to_system"))
        for object_name, mappings in obj_func_mapping.items():
            for mapping in mappings:
                model.call_edges.append(NormalizedCallEdge(contract_name, mapping[0], contract_name, object_name, "function_to_object", mapping[1]))

    for connection in context.high_connections:
        parent_name = connection["parent"]
        child_name = connection["child"]
        for variable_name, used_by in connection["var_func_mapping"].items():
            for function_name in used_by:
                model.call_edges.append(NormalizedCallEdge(parent_name, variable_name, child_name, function_name, "cross_type_state"))
        for source_name, targets in connection["func_func_mapping"].items():
            for target_name in targets:
                model.call_edges.append(NormalizedCallEdge(parent_name, source_name, child_name, target_name, "cross_type_call"))

    return model


class SolidityAdapterV0:
    def __init__(self):
        self.reader = legacy.ContractReader()

    def parse_source(self, source_path):
        lines = self.reader.read_file(source_path)
        unified_source = self.reader.unify_text(lines)
        parsed_rets, parsed_hierarchy, parsed_high_connections = self.reader(unified_source)
        context = SolidityAnalysisContext(
            path=source_path,
            language="solidity",
            reader=self.reader,
            lines=lines,
            unified_code=unified_source,
            rets=parsed_rets,
            hierarchy=parsed_hierarchy,
            high_connections=parsed_high_connections,
        )
        context.normalized_model = build_normalized_model(context)
        context.bind_legacy_runtime()
        return context

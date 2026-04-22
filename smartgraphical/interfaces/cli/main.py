import json
import os
import sys
import time

from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0, build_c_rule_registry
from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0, build_rule_registry
from smartgraphical.core.engine import RuleEngine, demonstrate_findings, summarize_model
from smartgraphical.services.analysis_service import AnalysisService


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


TASK_PROMPT = "\n 1: Old version\n \
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
Enter task number:  "

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2

ALLOWED_MODES = ("legacy", "auditor", "explore")
ALLOWED_OUTPUT_FORMATS = ("text", "json")
LANG_FROM_EXTENSION = {
    ".sol": "solidity",
    ".c": "c",
    ".h": "c",
}


class CliUserError(ValueError):
    """Raised for invalid CLI input provided by the user."""


def _build_service(language):
    if language == "solidity":
        return AnalysisService(
            adapter=SolidityAdapterV0(),
            rule_engine=RuleEngine(build_rule_registry()),
        )
    if language == "c":
        return AnalysisService(
            adapter=CBaseAdapterV0(),
            rule_engine=RuleEngine(build_c_rule_registry()),
        )
    raise CliUserError("Error: lang must be one of solidity or c.")


def _resolve_language(source_path, explicit_language):
    if explicit_language:
        language = explicit_language.lower()
        if language not in ("solidity", "c"):
            raise CliUserError("Error: lang must be one of solidity or c.")
        return language
    _, extension = os.path.splitext(source_path)
    language = LANG_FROM_EXTENSION.get(extension.lower())
    if language:
        return language
    raise CliUserError(
        "Error: cannot infer lang from extension; pass lang explicitly (solidity or c)."
    )


def parse_cli_args(argv):
    if len(argv) < 2:
        raise CliUserError(
            "Error: Please provide a source filename (ex: python sg_cli.py contract.sol)."
        )
    if not argv[1]:
        raise CliUserError("Error: Filename cannot be empty or None.")
    source_path = argv[1]
    if not os.path.isfile(source_path):
        raise CliUserError(f"Error: source file not found: {source_path}")

    selected_task = None
    output_mode = "legacy"
    output_format = "text"
    explicit_language = None
    if len(argv) >= 3:
        selected_task = argv[2]
    if len(argv) >= 4:
        output_mode = argv[3].lower()
    if len(argv) >= 5:
        output_format = argv[4].lower()
    if len(argv) >= 6:
        explicit_language = argv[5]
    if output_mode not in ALLOWED_MODES:
        raise CliUserError("Error: mode must be one of legacy, auditor, or explore.")
    if output_format not in ALLOWED_OUTPUT_FORMATS:
        raise CliUserError("Error: output format must be one of text or json.")
    if selected_task is not None and not str(selected_task).strip():
        raise CliUserError("Error: task cannot be empty.")
    language = _resolve_language(source_path, explicit_language)
    return source_path, selected_task, output_mode, output_format, language


def select_task_interactively():
    print(HELP_TEXT)
    selected_task = input(TASK_PROMPT)
    print("task    ", selected_task)
    return selected_task


def run_cli(source_path, selected_task=None, output_mode="legacy", output_format="text", language=None):
    started_at = time.perf_counter()
    language = language or _resolve_language(source_path, None)
    service = _build_service(language)
    context = service.analyze(source_path)
    model = getattr(context, "normalized_model", None)
    if model is None:
        raise RuntimeError("normalized model is missing from analysis context")
    if selected_task is None:
        selected_task = select_task_interactively()

    selected_task = str(selected_task).strip()
    findings = []
    rules_run = []
    rendered_graph = False

    if output_mode == "explore":
        summarize_model(context)

    if selected_task in service.rule_engine.rule_registry:
        findings = service.run_task(context, selected_task)
        rules_run = [selected_task]
    elif selected_task == "12":
        service.render_graph(context)
        rendered_graph = True
    elif selected_task == "13":
        findings = service.run_all(context)
        rules_run = sorted(service.rule_engine.rule_registry.keys(), key=int)
        service.render_graph(context)
        rendered_graph = True
    else:
        allowed_tasks = sorted(service.rule_engine.rule_registry.keys(), key=int)
        raise CliUserError(
            f"Error: task must be one of [{', '.join(allowed_tasks)}], 12, or 13."
        )

    if findings and output_format == "text":
        demonstrate_findings(findings, output_mode)
    elif not findings and selected_task != "12" and output_format == "text":
        print("No findings.")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = {
        "artifact": model.artifact.path,
        "language": language,
        "mode": output_mode,
        "task": selected_task,
        "rules_run": rules_run,
        "findings_count": len(findings),
        "graph_rendered": rendered_graph,
        "duration_ms": duration_ms,
    }
    if output_format == "json":
        print(json.dumps(report, sort_keys=False))
    return report


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        source_path, selected_task, output_mode, output_format, language = parse_cli_args(argv)
        run_cli(source_path, selected_task, output_mode, output_format, language)
        return EXIT_OK
    except CliUserError as exc:
        print(str(exc))
        return EXIT_USAGE_ERROR
    except Exception as exc:
        print("Error: internal failure during analysis.")
        print(f"Reason: {exc}")
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())

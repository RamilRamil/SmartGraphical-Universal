import sys

from smartgraphical.core.engine import demonstrate_findings, summarize_model
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


def parse_cli_args(argv):
    if len(argv) < 2:
        print("Error: Please provide a Solidity filename as an argument (ex: python SmartGraphical.py contract1.sol)")
        sys.exit(1)
    if not argv[1]:
        print("Error: Filename cannot be empty or None.")
        sys.exit(1)

    selected_task = None
    output_mode = "legacy"
    if len(argv) >= 3:
        selected_task = argv[2]
    if len(argv) >= 4:
        output_mode = argv[3].lower()
    if output_mode not in ["legacy", "auditor", "explore"]:
        print("Error: mode must be one of legacy, auditor, or explore.")
        sys.exit(1)
    return argv[1], selected_task, output_mode


def select_task_interactively():
    print(HELP_TEXT)
    selected_task = input(TASK_PROMPT)
    print("task    ", selected_task)
    return selected_task


def run_cli(source_path, selected_task=None, output_mode="legacy"):
    service = AnalysisService()
    context = service.analyze(source_path)
    if selected_task is None:
        selected_task = select_task_interactively()

    if output_mode == "explore":
        summarize_model(context)

    if selected_task in service.rule_engine.rule_registry:
        findings = service.run_task(context, selected_task)
        demonstrate_findings(findings, output_mode)
        return

    if selected_task == "12":
        service.render_graph(context)
        return

    if selected_task == "13":
        findings = service.run_all(context)
        demonstrate_findings(findings, output_mode)
        service.render_graph(context)
        return

    print("Error: task must be a value from 1 to 13.")
    sys.exit(1)


def main(argv=None):
    if argv is None:
        argv = sys.argv
    source_path, selected_task, output_mode = parse_cli_args(argv)
    run_cli(source_path, selected_task, output_mode)


if __name__ == "__main__":
    main()

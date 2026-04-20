# SmartGraphical
SmartGraphical: a Solidity Contract Logical Vulnerability Scanner and Graphical representation

## Origin and this fork

The foundation comes from the original project by **[mohamadpishdar](https://github.com/mohamadpishdar)**:
[github.com/mohamadpishdar/SmartGraphical](https://github.com/mohamadpishdar/SmartGraphical). Thank you for the initial idea and implementation.

This repository **continues, improves, and extends** that work (robustness, features, checks, and documentation evolve over time). The goal is to keep the same overall approach while making the tool more useful and maintainable.

The upstream project did not include a standalone `LICENSE` file; this README keeps **clear attribution** to the original author. If a license is added upstream later, this fork should stay aligned with it.

## Documentation in this fork

- `PROJECT_VISION.md` — intent and direction of this fork (auditor-centric, pragmatic parsing).
- `NEXT_STEPS_PLAN.md` — phased roadmap (CLI hardening, tests, web layer, second language PoC).

# How to Use:

Primary entrypoint (use `python3` if `python` is not on your PATH):

- `python3 sg_cli.py ContractFile`
- `python3 sg_cli.py ContractFile 8`
- `python3 sg_cli.py ContractFile 13 auditor`
- `python3 sg_cli.py ContractFile 12 explore`

The modular CLI supports both the original interactive flow (run without a task number) and direct task execution.

Note: the historical monolithic `SmartGraphical.py` entrypoint is **not present** in this repository layout; use `sg_cli.py` and `smartgraphical.interfaces.cli.main` instead.

Available output modes:

- `legacy` keeps the original alert-style output
- `auditor` prints findings with category, portability, confidence, evidence, and remediation hint
- `explore` prints a normalized model summary before the findings or graph

Dependency note:

- analysis modes work without `graphviz`
- graph rendering requires the `graphviz` Python package to be installed

## Internal Architecture

The current implementation keeps Solidity-focused heuristics (pragmatic string/regex style parsing, not a full compiler frontend), organized for extension:

- `SolidityAdapterV0` (`smartgraphical/adapters/solidity/adapter.py`) parses Solidity source, builds an `AnalysisContext`, and fills a `NormalizedAuditModel` (types, functions, state entities, call edges, and derived facts such as guards, mutations, transfers, computations; plus optional exploration/findings buckets where populated).
- Rule implementations live under `smartgraphical/core/rules/` and are registered in `build_rule_registry()` inside the adapter module.
- `RuleEngine` runs a task id `1`–`11` by calling the registered runner; runners emit structured `Finding` objects (built via shared helpers that attach evidence from the normalized model where possible).
- `GraphBuilder` renders the graph from the normalized model.

Orchestration: `AnalysisService` (`smartgraphical/services/analysis_service.py`) wires adapter, `RuleEngine`, and `GraphBuilder` for CLI use.

## Project Structure

```text
smartgraphical/
  core/
    model.py
    findings.py
    engine.py
    graph.py
    rules/
      (task runners: naming, state_mutation, staking, ...)
  adapters/
    solidity/
      adapter.py
      reader.py
      helpers.py
  services/
    analysis_service.py
  interfaces/
    cli/
      main.py
    web_api/
    web_app/
sg_cli.py
```

Current roles:

- `sg_cli.py` is the thin CLI entrypoint (delegates to `smartgraphical/interfaces/cli/main.py`).
- `smartgraphical/core` holds the shared model, findings, engine, graph, and rule modules.
- `smartgraphical/adapters/solidity/` contains `SolidityAdapterV0`, the Solidity reader, and helper extractors used when building the normalized model.
- `smartgraphical/services/analysis_service.py` orchestrates parsing, rule execution, and graph rendering.
- `smartgraphical/interfaces/web_api` and `smartgraphical/interfaces/web_app` are placeholders for future HTTP layers.

## Rule Groups

- `NamingAndConsistency`: Tasks `1`, `10`
- `StateAndMutation`: Tasks `2`, `4`, `11`
- `FlowAndOrdering`: Tasks `6`, `8`, `9`
- `ComputationAndEconomics`: Tasks `3`, `5`, `7`
- `VisualizationOnly`: Task `12` (graph only)

CLI task `12` renders the overview graph. Task `13` runs all rules `1`–`11`, prints findings, then renders the graph (same behavior as the interactive menu option).

## Portability Direction

The long-term direction is to keep the review principle portable across languages such as `Rust` and `C++`. The current codebase now defines a normalized layer and a minimal second-language proof-of-concept target:

- extract `FunctionLike`, `StateEntity`, `CallSite`, `Guard`, and `Mutation`
- run at least two portable rules on that normalized model
- render the same overview graph from the normalized model

# SmartGraphical checks the Tasks below:

Task 1: The signatures associated with the function definitions in every function of the smart contract code must be examined and updated if the contract is the outcome of a rewrite or update of another contract. If this isn't done, the contract may have a logical issue, and information from the previous signature may be given to the functions using the programmer's imagination. This inevitably indicates that the contract code contains a runtime error.

Task 2: In the event that the developer modifies contract parameters, such as the maximum fee or user balance, or other elements, like totalSupply, that are determined by another contract. This could be risky and result in warnings being generated. Generally speaking, obtaining any value from a source outside the contract may have a different value under various circumstances, which could lead to a smart contract logical error. For instance, the programmer might not have incorporated the input's fluctuation or range into the program logic

Task 3: The quantity of collateral determines one of the typical actions in DeFi smart contracts, in addition to stake and unstake. Attacks like multiple borrowing without collateral might result from logical mistakes made by the developer when releasing this collateral, determining the maximum loan amount that can be given, and determining the kind and duration of the collateral encumbrance

Tasks 3 and 5 and 9: When a smart contract receives value, like financial tokens or game points (from staking assets, depositing points, or depositing tokens), it must perform a logical check when the assets are removed from the system to ensure that no user can circumvent the program's logic and take more money out of the contract than they are actually entitled to.

Tasks 2 and 4: All token supply calculations must be performed accurately and completely. Even system security and authentication might be taken into account, but the communication method specification is entirely incorrect. For instance, one of the several errors made by developers has been the presence of a function like burn that can remove tokens from the pool or functions identical to it that can add tokens to the pool. To determine whether this is necessary in terms of program logic and whether other supply changes are taken into account in this computation, these conditions should be looked at. No specific function is required, and burning tokens can be moved to an address as a transaction without being returned. 

Task 2 and 5 and 9: There are various incentive aspects in many smart contracts that defy logic. For instance, if the smart contract has a point system for burning tokens, is it possible to use that point in other areas of the contract? It is crucial to examine the income and spending points in this situation. For instance, the developer can permit spending without making sure the user validates the point earning. The program logic may be abused as a result of this. 

Task 6: The code's error conditions need to be carefully examined. For instance, a logical error and a serious blow to the smart contract can result from improperly validating the error circumstances. Assume, for instance, that the programmer uses a system function to carry out a non-deterministic transport, but its error management lacks a proper understanding of the system state. In the event of an error, for instance, the coder attempts to reverse the system state; however, this may not be logically sound and could result in misuse of the smart contract by, for instance, reproducing an unauthorized activity in the normal state. 

Task 7: Logical errors can result from any complicated coding calculations. For instance, a cyber attacker may exploit the program logic by forcing their desired computation output if the coder fails to properly analyze the code output under various scenarios.

Tasks 8 and 9: A smart contract's execution output might be impacted by the sequence in which certain procedures are carried out. The developer measuring or calculating the price of a token (or anything similar) and then transferring the asset at a certain time period is one of the most prevalent examples of this kind of vulnerability. Given that the attacker can manipulate the market through fictitious fluctuations, this is a logical issue. Thus, this gives the attacker the ability to remove the asset from the agreement. 

Task 10: In a smart contract, using names that are spelled similarly to one another may cause logical issues. For instance, the coder might inadvertently substitute one of these definitions for another in the contract, which would be undetectable during the coder's initial tests. There is a chance that a cybercriminal will take advantage of this scenario. 

Task 11: A smart contract's function that can be called fully publicly and without limitations may be risky and necessitate additional research from the developer if it modifies variables, delivers inventory, or does something similar



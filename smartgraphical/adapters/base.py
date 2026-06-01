"""Shared adapter contract for SmartGraphical language adapters.

Every language adapter (Solidity, C/Solana, Rust/Stellar) implements this single
contract so the analysis service and the web facade can treat them uniformly.
See the project constitution, Principle III (Normalized Model Is the Contract)
and Principle IV (Portability Across Languages).

The contract is structural (``typing.Protocol``). Conformance is enforced at
test time by ``tests/unit/test_adapter_contract_conformance.py`` (via
``inspect.signature``) rather than by inheritance, to avoid a base-class import
cycle and to keep adapters independently constructable.

Reference: ``specs/011-adapter-contract-ci/contracts/adapter-contract.md``.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from smartgraphical.core.model import AnalysisContext


@runtime_checkable
class AnalysisAdapter(Protocol):
    """One analysis entry point shared by all language adapters.

    Contract rules:

    - R1 (single signature): ``parse_source(source_path, *,
      expand_local_imports=True)`` -- one positional argument and one
      keyword-only flag, nothing more required.
    - R2 (uniform flag): ``expand_local_imports`` is accepted by every adapter.
      Adapters without local-import expansion (C and Rust today) treat it as a
      documented no-op and never raise because of it.
    - R3 (return shape): returns an ``AnalysisContext`` whose ``normalized_model``
      is a populated ``NormalizedAuditModel``.
    - R4 (backward compatibility): the Solidity adapter is the reference
      implementation; its behavior and output must not change.
    - R5 (no heavy dependency): implementing this contract must not add an
      AST/grammar/parser dependency (Principle I).
    """

    def parse_source(
        self,
        source_path: str,
        *,
        expand_local_imports: bool = True,
    ) -> AnalysisContext:
        ...

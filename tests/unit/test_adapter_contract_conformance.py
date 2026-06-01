"""Adapter contract conformance (feature 011).

Every registered language adapter MUST implement the shared ``AnalysisAdapter``
contract (``smartgraphical/adapters/base.py``): one
``parse_source(source_path, *, expand_local_imports=True) -> AnalysisContext``,
with the flag accepted for every language (a no-op where local-import expansion
is not implemented). This test is the enforcement teeth for constitution
Principle III; it fails and names the offending adapter on signature drift.

Reference: ``specs/011-adapter-contract-ci/contracts/adapter-contract.md``.
"""
import inspect
import os
import unittest

from smartgraphical.adapters.base import AnalysisAdapter
from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0
from smartgraphical.adapters.rust_stellar.adapter import RustStellarAdapterV0
from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.core.model import AnalysisContext

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO_ROOT, "fixtures")

# (label, adapter instance, fixture path) for every registered adapter.
CASES = [
    ("solidity", SolidityAdapterV0(), os.path.join(FIXTURES, "solidity", "MinimalGuard.sol")),
    ("c", CBaseAdapterV0(), os.path.join(FIXTURES, "c", "MinimalTu.c")),
    ("rust", RustStellarAdapterV0(), os.path.join(FIXTURES, "rust", "SorobanViolations.rs")),
]


def _required_positional(sig):
    return [
        name
        for name, p in sig.parameters.items()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty
    ]


class AdapterContractConformanceTests(unittest.TestCase):
    def test_signature_accepts_expand_local_imports(self):
        # R1/R2: the keyword-only flag is part of every adapter's signature.
        for label, adapter, _ in CASES:
            with self.subTest(adapter=label):
                sig = inspect.signature(adapter.parse_source)
                self.assertIn(
                    "expand_local_imports",
                    sig.parameters,
                    f"{type(adapter).__name__}.parse_source must accept "
                    f"'expand_local_imports' (adapter contract R1/R2)",
                )

    def test_no_required_positional_beyond_source_path(self):
        # R1: only source_path is required positionally.
        for label, adapter, _ in CASES:
            with self.subTest(adapter=label):
                sig = inspect.signature(adapter.parse_source)
                required = _required_positional(sig)
                self.assertEqual(
                    required,
                    ["source_path"],
                    f"{type(adapter).__name__}.parse_source must require only "
                    f"'source_path' positionally (contract R1); got {required}",
                )

    def test_returns_context_for_both_flag_values(self):
        # R2/R3: both flag values return an AnalysisContext with a real model.
        for label, adapter, fixture in CASES:
            with self.subTest(adapter=label):
                self.assertTrue(os.path.isfile(fixture), f"missing fixture {fixture}")
                for flag in (True, False):
                    ctx = adapter.parse_source(fixture, expand_local_imports=flag)
                    self.assertIsInstance(
                        ctx,
                        AnalysisContext,
                        f"{type(adapter).__name__}.parse_source must return "
                        f"AnalysisContext (contract R3)",
                    )
                    self.assertIsNotNone(
                        ctx.normalized_model,
                        f"{type(adapter).__name__} must return a non-null "
                        f"normalized_model (contract R3)",
                    )

    def test_runtime_protocol_membership(self):
        # Structural @runtime_checkable membership (method presence).
        for label, adapter, _ in CASES:
            with self.subTest(adapter=label):
                self.assertIsInstance(adapter, AnalysisAdapter)


if __name__ == "__main__":
    unittest.main()

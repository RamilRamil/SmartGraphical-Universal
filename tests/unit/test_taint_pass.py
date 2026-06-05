"""Unit tests for the intra-procedural taint pass (feature 015)."""
import unittest

from smartgraphical.core.dataflow import taint
from smartgraphical.core.model import (
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedGuardFact,
    NormalizedType,
)


def fn(inputs=None, stmts=None, mutations=None, guards=None):
    return NormalizedFunction(
        name="f",
        owner="C",
        inputs=inputs or [],
        exploration_statements=stmts or [],
        mutations=mutations or [],
        guard_facts=[
            NormalizedGuardFact(guard_type="require", expression=g) for g in (guards or [])
        ],
    )


class ComputeTaintTests(unittest.TestCase):
    def test_unguarded_source_to_sink(self):
        paths = taint.compute_taint(fn(inputs=["v"], stmts=["balance = v", "transfer(to, v)"]))
        self.assertTrue(
            any(p["source"] == "v" and p["sink"] == "transfer" and not p["guarded"] for p in paths)
        )

    def test_typed_local_from_source_reaches_sink(self):
        paths = taint.compute_taint(
            fn(inputs=[], stmts=["int n = recv(sock)", "memcpy(buf, n)"])
        )
        self.assertTrue(any(p["sink"] == "memcpy" and not p["guarded"] for p in paths))

    def test_guarded_flow(self):
        paths = taint.compute_taint(fn(inputs=["v"], stmts=["require(v > 0)", "transfer(to, v)"]))
        sinks = [p for p in paths if p["sink"] == "transfer"]
        self.assertTrue(sinks)
        self.assertTrue(all(p["guarded"] for p in sinks))

    def test_no_flow(self):
        self.assertEqual(taint.compute_taint(fn(inputs=["v"], stmts=["uint x = 1", "log(x)"])), [])

    def test_mutation_is_a_sink(self):
        paths = taint.compute_taint(
            fn(inputs=["amount"], stmts=["balance = amount"], mutations=["balance = amount"])
        )
        self.assertTrue(any(p["source"] == "amount" for p in paths))

    def test_deterministic(self):
        f = fn(inputs=["v"], stmts=["balance = v", "transfer(to, v)"])
        self.assertEqual(taint.compute_taint(f), taint.compute_taint(f))


class ApplyTaintTests(unittest.TestCase):
    def test_apply_sets_field_on_functions(self):
        f = fn(inputs=["v"], stmts=["transfer(to, v)"])
        model = NormalizedAuditModel(
            artifact=NormalizedArtifact(path="x", language="c", adapter_name="c_base"),
            types=[NormalizedType(name="C", kind="contract", functions=[f])],
        )
        taint.apply_taint(model)
        self.assertTrue(f.taint_paths)
        self.assertEqual(f.taint_paths[0]["sink"], "transfer")


if __name__ == "__main__":
    unittest.main()

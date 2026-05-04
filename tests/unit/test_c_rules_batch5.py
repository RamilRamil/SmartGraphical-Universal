"""Unit tests for C rules 116-120."""
import unittest

from smartgraphical.adapters.c_base.adapter import build_c_rule_registry
from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.c.c_specific.signed_integer_overflow_consensus import (
    run as run_signed_overflow,
)
from smartgraphical.core.rules.c.c_specific.unspecified_evaluation_order_side_effects import (
    run as run_unspecified_order,
)
from smartgraphical.core.rules.c_node.node_specific.protocol_struct_padding_mismatch import (
    run as run_struct_padding,
)
from smartgraphical.core.rules.c_node.node_specific.unaligned_memory_access_ebpf import (
    run as run_unaligned_access,
)
from smartgraphical.core.rules.c.portable_with_adapter.division_rounding_divergence import (
    run as run_division_rounding,
)


def _context(statements):
    artifact = NormalizedArtifact(path='test.c', language='c', adapter_name='Test')
    model = NormalizedAuditModel(artifact=artifact)
    unit = NormalizedType(name='test_unit', kind='translation_unit')
    unit.functions.append(NormalizedFunction(
        name='target',
        owner='test_unit',
        exploration_statements=list(statements),
    ))
    model.types.append(unit)
    return AnalysisContext(
        path='test.c',
        language='c',
        reader=None,
        lines=[],
        unified_code='',
        rets=[],
        hierarchy={},
        high_connections=[],
        normalized_model=model,
    )


class SignedOverflowRuleTests(unittest.TestCase):

    def test_signed_add_in_runtime_alerts(self):
        ctx = _context(['long new_balance = old_balance + reward_in_runtime'])
        findings = run_signed_overflow(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '116')

    def test_builtin_overflow_guard_is_silent(self):
        ctx = _context(['__builtin_add_overflow( old_balance, reward, &new_balance )'])
        self.assertEqual(run_signed_overflow(ctx), [])


class UnspecifiedEvalOrderRuleTests(unittest.TestCase):

    def test_two_side_effect_calls_as_args_alerts(self):
        ctx = _context(['process_tx( update_hash(a), update_hash(b) )'])
        findings = run_unspecified_order(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '117')

    def test_precomputed_args_are_silent(self):
        ctx = _context(['process_tx( h1, h2 )'])
        self.assertEqual(run_unspecified_order(ctx), [])


class StructPaddingRuleTests(unittest.TestCase):

    def test_protocol_struct_without_packed_alerts(self):
        ctx = _context([
            'struct shred { uchar type',
            'ulong slot',
            '}',
            'hdr = (struct shred *)packet_buffer',
        ])
        findings = run_struct_padding(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '118')

    def test_packed_struct_is_silent(self):
        ctx = _context([
            'struct __attribute__((packed)) shred { uchar type',
            'ulong slot',
            '}',
            'hdr = (struct shred *)packet_buffer',
        ])
        self.assertEqual(run_struct_padding(ctx), [])


class DivisionRoundingRuleTests(unittest.TestCase):

    def test_signed_division_in_consensus_context_alerts(self):
        ctx = _context(['long daily_rate = total_debt / days_remaining_for_reward_balance'])
        findings = run_division_rounding(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '119')

    def test_euclidean_helper_is_silent(self):
        ctx = _context(['long daily_rate = fd_long_div_euclidean( total_debt, days_remaining )'])
        self.assertEqual(run_division_rounding(ctx), [])


class UnalignedAccessRuleTests(unittest.TestCase):

    def test_vm_cast_store_without_guard_alerts(self):
        ctx = _context(['*(ulong *)(vm->mem + addr) = val'])
        findings = run_unaligned_access(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '120')

    def test_alignment_guard_suppresses_alert(self):
        ctx = _context([
            'if( addr & 0x7 ) return FD_VM_ERR_UNALIGNED',
            '*(ulong *)(vm->mem + addr) = val',
        ])
        self.assertEqual(run_unaligned_access(ctx), [])


class CRuleRegistryBatch5Tests(unittest.TestCase):

    def test_registry_contains_116_to_120(self):
        registry = build_c_rule_registry()
        for task_id in ('116', '117', '118', '119', '120'):
            self.assertIn(task_id, registry)


if __name__ == '__main__':
    unittest.main()

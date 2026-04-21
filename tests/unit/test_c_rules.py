"""Unit tests for all 6 C/node rule modules on synthetic NormalizedAuditModel.

Each rule is tested with at minimum one positive case (should alert) and
one negative case (should be silent). No C parsing or adapter is involved;
model instances are built directly.
"""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.c_node.incomplete_reserved_account_list import (
    run as run_reserved,
)
from smartgraphical.core.rules.c_node.non_saturating_float_cast import (
    run as run_float_cast,
)
from smartgraphical.core.rules.c_node.shared_mem_uaf_pool import (
    run as run_uaf,
)
from smartgraphical.core.rules.c_node.sysvar_decode_callback_type_mismatch import (
    run as run_sysvar,
)
from smartgraphical.core.rules.c_node.unchecked_return_sensitive import (
    run as run_unchecked,
)
from smartgraphical.core.rules.c_node.unsafe_shift_external_exponent import (
    run as run_shift,
)


def _context(statements, unified_code=''):
    artifact = NormalizedArtifact(path='test.c', language='c', adapter_name='Test')
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name='test_unit', kind='translation_unit')
    type_entry.functions.append(NormalizedFunction(
        name='target',
        owner='test_unit',
        exploration_statements=list(statements),
    ))
    model.types.append(type_entry)
    return AnalysisContext(
        path='test.c', language='c', reader=None, lines=[],
        unified_code=unified_code, rets=[], hierarchy={},
        high_connections=[], normalized_model=model,
    )


# ---------------------------------------------------------------------------
# Rule 101: non_saturating_float_cast
# ---------------------------------------------------------------------------

class FloatCastRuleTests(unittest.TestCase):

    def test_direct_cast_to_ulong_alerts(self):
        ctx = _context(['ulong lamports = (ulong)calculated_double'])
        findings = run_float_cast(ctx)
        self.assertTrue(findings)
        self.assertIn('float-to-uint', findings[0].message)

    def test_direct_cast_to_uint64_t_alerts(self):
        ctx = _context(['uint64_t val = (uint64_t)some_double'])
        self.assertTrue(run_float_cast(ctx))

    def test_saturating_wrapper_is_silent(self):
        ctx = _context(['ulong x = fd_rust_cast_double_to_ulong(val)'])
        self.assertEqual(run_float_cast(ctx), [])

    def test_fd_saturating_prefix_is_silent(self):
        ctx = _context(['ulong x = fd_saturating_add(a, b)'])
        self.assertEqual(run_float_cast(ctx), [])

    def test_no_cast_statement_is_silent(self):
        ctx = _context(['ulong x = y + z'])
        self.assertEqual(run_float_cast(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['ulong v = (ulong)d'])
        findings = run_float_cast(ctx)
        self.assertEqual(findings[0].task_id, '101')
        self.assertEqual(findings[0].rule_id, 'non_saturating_float_cast')


# ---------------------------------------------------------------------------
# Rule 102: unsafe_shift_external_exponent
# ---------------------------------------------------------------------------

class ShiftRuleTests(unittest.TestCase):

    def test_shift_from_pkt_field_alerts(self):
        ctx = _context(['ulong rtt = base << pkt->peer_ack_delay_exponent'])
        findings = run_shift(ctx)
        self.assertTrue(findings)
        self.assertIn('bound check', findings[0].message)

    def test_shift_from_conn_field_alerts(self):
        ctx = _context(['ulong val = x << conn->exponent'])
        self.assertTrue(run_shift(ctx))

    def test_prior_bound_check_suppresses_alert(self):
        ctx = _context([
            'if pkt->peer_ack_delay_exponent < 64',
            'ulong rtt = base << pkt->peer_ack_delay_exponent',
        ])
        self.assertEqual(run_shift(ctx), [])

    def test_inline_mask_suppresses_alert(self):
        ctx = _context(['ulong rtt = base << (pkt->exp & 0x3f)'])
        self.assertEqual(run_shift(ctx), [])

    def test_literal_exponent_is_silent(self):
        ctx = _context(['ulong flags = 1 << 5'])
        self.assertEqual(run_shift(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['ulong v = x << pkt->exp'])
        findings = run_shift(ctx)
        self.assertEqual(findings[0].task_id, '102')
        self.assertEqual(findings[0].rule_id, 'unsafe_shift_external_exponent')


# ---------------------------------------------------------------------------
# Rule 103: unchecked_return_sensitive
# ---------------------------------------------------------------------------

class UncheckedReturnRuleTests(unittest.TestCase):

    def test_standalone_sha256_call_alerts(self):
        ctx = _context(['fd_sha256_hash( data, sz, hash )'])
        findings = run_unchecked(ctx)
        self.assertTrue(findings)
        self.assertIn('fd_sha256_hash', findings[0].message)

    def test_standalone_verify_call_alerts(self):
        ctx = _context(['fd_ed25519_verify( sig, pk, msg )'])
        self.assertTrue(run_unchecked(ctx))

    def test_assigned_call_is_silent(self):
        ctx = _context(['int rc = fd_sha256_hash( data, sz, hash )'])
        self.assertEqual(run_unchecked(ctx), [])

    def test_if_guarded_call_is_silent(self):
        ctx = _context(['if FD_UNLIKELY( !fd_sha256_hash( data, sz, hash ) )'])
        self.assertEqual(run_unchecked(ctx), [])

    def test_return_of_call_is_silent(self):
        ctx = _context(['return fd_sha256_hash( data, sz, hash )'])
        self.assertEqual(run_unchecked(ctx), [])

    def test_unrelated_api_is_silent(self):
        ctx = _context(['fd_log_notice( "hello" )'])
        self.assertEqual(run_unchecked(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['fd_sha256_hash( d, n, h )'])
        findings = run_unchecked(ctx)
        self.assertEqual(findings[0].task_id, '103')
        self.assertEqual(findings[0].rule_id, 'unchecked_return_sensitive')


# ---------------------------------------------------------------------------
# Rule 104: shared_mem_uaf_pool
# ---------------------------------------------------------------------------

class UafPoolRuleTests(unittest.TestCase):

    def test_dereference_after_release_alerts(self):
        ctx = _context([
            'fd_executor_release( elem )',
            'return elem->status',
        ])
        findings = run_uaf(ctx)
        self.assertTrue(findings)
        self.assertIn("'elem'", findings[0].message)

    def test_null_assignment_after_release_is_silent(self):
        ctx = _context([
            'fd_executor_release( elem )',
            'elem = NULL',
            'return 0',
        ])
        self.assertEqual(run_uaf(ctx), [])

    def test_reassignment_after_release_is_silent(self):
        ctx = _context([
            'fd_executor_release( elem )',
            'elem = pool_acquire()',
            'use(elem->data)',
        ])
        self.assertEqual(run_uaf(ctx), [])

    def test_no_release_no_alert(self):
        ctx = _context([
            'process( elem )',
            'return elem->status',
        ])
        self.assertEqual(run_uaf(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context([
            'fd_executor_release( x )',
            'use(x->field)',
        ])
        findings = run_uaf(ctx)
        self.assertEqual(findings[0].task_id, '104')
        self.assertEqual(findings[0].rule_id, 'shared_mem_uaf_pool')


# ---------------------------------------------------------------------------
# Rule 105: incomplete_reserved_account_list
# ---------------------------------------------------------------------------

class ReservedAccountRuleTests(unittest.TestCase):

    def test_registry_missing_sysvars_alerts(self):
        source = (
            'static const char * fd_pack_unwritable[] = {\n'
            '    "11111111111111111111111111111111",\n'
            '};\n'
        )
        ctx = _context([], unified_code=source)
        findings = run_reserved(ctx)
        self.assertTrue(findings)
        messages = ' '.join(f.message for f in findings)
        self.assertIn('SysvarC1ock', messages)

    def test_no_registry_marker_is_silent(self):
        ctx = _context([], unified_code='void foo() { int x = 1; }')
        self.assertEqual(run_reserved(ctx), [])

    def test_empty_source_is_silent(self):
        ctx = _context([], unified_code='')
        self.assertEqual(run_reserved(ctx), [])

    def test_finding_metadata_is_populated(self):
        source = 'static void fd_pack_unwritable_setup() {}\n'
        ctx = _context([], unified_code=source)
        findings = run_reserved(ctx)
        if findings:
            self.assertEqual(findings[0].task_id, '105')
            self.assertEqual(findings[0].rule_id, 'incomplete_reserved_account_list')


# ---------------------------------------------------------------------------
# Rule 106: sysvar_decode_callback_type_mismatch
# ---------------------------------------------------------------------------

class SysvarDecodeMismatchTests(unittest.TestCase):

    def test_void_cast_on_decode_field_alerts(self):
        ctx = _context(['sysvar->decode = (void *)my_decode_func'])
        findings = run_sysvar(ctx)
        self.assertTrue(findings)
        self.assertIn('type cast', findings[0].message)

    def test_fd_fn_t_cast_on_decode_field_alerts(self):
        ctx = _context(['entry->decode = (fd_sysvar_fn_t *)other_func'])
        self.assertTrue(run_sysvar(ctx))

    def test_direct_assignment_without_cast_is_silent(self):
        ctx = _context(['sysvar->decode = my_decode_func'])
        self.assertEqual(run_sysvar(ctx), [])

    def test_unrelated_pointer_assignment_is_silent(self):
        ctx = _context(['conn->handler = (void *)my_handler'])
        self.assertEqual(run_sysvar(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['sv->decode = (void *)fn'])
        findings = run_sysvar(ctx)
        self.assertEqual(findings[0].task_id, '106')
        self.assertEqual(findings[0].rule_id, 'sysvar_decode_callback_type_mismatch')


if __name__ == '__main__':
    unittest.main()

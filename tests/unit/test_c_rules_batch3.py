"""Unit tests for C rules 110, 112, 114 on synthetic NormalizedAuditModel."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.c.c_specific.bank_lifecycle_refcount_concurrency import (
    run as run_bank,
)
from smartgraphical.core.rules.c_node.node_specific.alt_resolution_window_mismatch import (
    run as run_alt,
)
from smartgraphical.core.rules.c_node.node_specific.bls_aggregate_rogue_key_check import (
    run as run_bls,
)


def _context(statements):
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
        unified_code='', rets=[], hierarchy={},
        high_connections=[], normalized_model=model,
    )


# ---------------------------------------------------------------------------
# Rule 110: bank_lifecycle_refcount_concurrency
# ---------------------------------------------------------------------------

class BankRefcountRuleTests(unittest.TestCase):

    def test_postfix_increment_on_ref_cnt_alerts(self):
        ctx = _context(['bank->ref_cnt++'])
        findings = run_bank(ctx)
        self.assertTrue(findings)
        self.assertIn("'ref_cnt'", findings[0].message)

    def test_postfix_decrement_on_ref_count_alerts(self):
        ctx = _context(['b->ref_count--'])
        findings = run_bank(ctx)
        self.assertTrue(findings)
        self.assertIn("'ref_count'", findings[0].message)

    def test_atomic_increment_is_silent(self):
        ctx = _context(['__atomic_fetch_add( &bank->ref_cnt, 1, __ATOMIC_SEQ_CST )'])
        self.assertEqual(run_bank(ctx), [])

    def test_fd_helper_is_silent(self):
        ctx = _context(['fd_bank_ref_inc( bank )'])
        self.assertEqual(run_bank(ctx), [])

    def test_unrelated_field_increment_is_silent(self):
        ctx = _context(['ctx->frame_count++'])
        self.assertEqual(run_bank(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['bank->ref_cnt++'])
        findings = run_bank(ctx)
        self.assertEqual(findings[0].task_id, '110')
        self.assertEqual(findings[0].rule_id, 'bank_lifecycle_refcount_concurrency')


# ---------------------------------------------------------------------------
# Rule 112: alt_resolution_window_mismatch
# ---------------------------------------------------------------------------

class AltWindowRuleTests(unittest.TestCase):

    def test_wrong_constant_in_alt_check_alerts(self):
        ctx = _context(['if( current_slot - alt->deactivation_slot > 128 ) drop_tx()'])
        findings = run_alt(ctx)
        self.assertTrue(findings)
        self.assertIn('128', findings[0].message)
        self.assertIn('512', findings[0].message)

    def test_correct_constant_512_is_silent(self):
        ctx = _context(['if( current_slot - alt->deactivation_slot > 512 ) drop_tx()'])
        self.assertEqual(run_alt(ctx), [])

    def test_non_alt_context_is_silent(self):
        ctx = _context(['if( retry_count > 128 ) abort()'])
        self.assertEqual(run_alt(ctx), [])

    def test_lut_keyword_triggers_detection(self):
        ctx = _context(['if( slot - lut_deactivation_slot > 256 ) reject_tx()'])
        findings = run_alt(ctx)
        self.assertTrue(findings)
        self.assertIn('256', findings[0].message)

    def test_finding_metadata_is_populated(self):
        ctx = _context(['if( cur - alt->deactivation_slot > 64 ) drop()'])
        findings = run_alt(ctx)
        self.assertEqual(findings[0].task_id, '112')
        self.assertEqual(findings[0].rule_id, 'alt_resolution_window_mismatch')


# ---------------------------------------------------------------------------
# Rule 114: bls_aggregate_rogue_key_check
# ---------------------------------------------------------------------------

class BlsRogueKeyRuleTests(unittest.TestCase):

    def test_bls_sum_without_pop_alerts(self):
        ctx = _context(['aggregate_pk = bls_sum( validator_pks )'])
        self.assertTrue(run_bls(ctx))

    def test_bls_aggregate_without_pop_alerts(self):
        ctx = _context(['agg = bls12_aggregate( keys, n )'])
        self.assertTrue(run_bls(ctx))

    def test_pop_check_in_window_suppresses_alert(self):
        ctx = _context([
            'if( !bls_verify_pop( pk ) ) return ERR_BAD_POP',
            'aggregate_pk = bls_sum( validator_pks )',
        ])
        self.assertEqual(run_bls(ctx), [])

    def test_pop_check_after_aggregate_suppresses_alert(self):
        ctx = _context([
            'agg = bls_sum( pks )',
            'verify_pop( agg )',
        ])
        self.assertEqual(run_bls(ctx), [])

    def test_non_bls_aggregate_is_silent(self):
        ctx = _context(['total = sum_rewards( validators )'])
        self.assertEqual(run_bls(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['agg = bls12_aggregate( keys, n )'])
        findings = run_bls(ctx)
        self.assertEqual(findings[0].task_id, '114')
        self.assertEqual(findings[0].rule_id, 'bls_aggregate_rogue_key_check')


if __name__ == '__main__':
    unittest.main()

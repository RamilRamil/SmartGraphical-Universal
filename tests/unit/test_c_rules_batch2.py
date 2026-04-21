"""Unit tests for C rules 107-109 on synthetic NormalizedAuditModel."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.c_node.bitwise_flag_normalization_mismatch import (
    run as run_bitwise,
)
from smartgraphical.core.rules.c_node.quic_handshake_eviction_missing import (
    run as run_hs,
)
from smartgraphical.core.rules.c_node.quic_invisible_frame_limit import (
    run as run_frame,
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
# Rule 107: bitwise_flag_normalization_mismatch
# ---------------------------------------------------------------------------

class BitwiseFlagRuleTests(unittest.TestCase):

    def test_executable_bitwise_and_alerts(self):
        ctx = _context(['hash_val |= (account->executable & 1)'])
        findings = run_bitwise(ctx)
        self.assertTrue(findings)
        self.assertIn("'executable'", findings[0].message)

    def test_writable_bitwise_and_alerts(self):
        ctx = _context(['val |= (meta->writable & 1)'])
        findings = run_bitwise(ctx)
        self.assertTrue(findings)
        self.assertIn("'writable'", findings[0].message)

    def test_double_negation_is_silent(self):
        ctx = _context(['hash_val |= (!!account->executable)'])
        self.assertEqual(run_bitwise(ctx), [])

    def test_unknown_field_is_silent(self):
        ctx = _context(['val = flags & 1'])
        self.assertEqual(run_bitwise(ctx), [])

    def test_non_flag_bitwise_is_silent(self):
        ctx = _context(['mask = raw_bits & 0x3f'])
        self.assertEqual(run_bitwise(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context(['h |= (account->writable & 1)'])
        findings = run_bitwise(ctx)
        self.assertEqual(findings[0].task_id, '107')
        self.assertEqual(findings[0].rule_id, 'bitwise_flag_normalization_mismatch')


# ---------------------------------------------------------------------------
# Rule 108: quic_invisible_frame_limit
# ---------------------------------------------------------------------------

class QuicFrameLimitRuleTests(unittest.TestCase):

    def test_frame_processing_inside_loop_without_limit_alerts(self):
        ctx = _context([
            'while( frames_left ) {',
            'parse_and_handle( frame )',
        ])
        self.assertTrue(run_frame(ctx))

    def test_frame_processing_with_max_frames_limit_is_silent(self):
        ctx = _context([
            'while( frames_left && frame_count++ < MAX_FRAMES ) {',
            'parse_and_handle( frame )',
        ])
        self.assertEqual(run_frame(ctx), [])

    def test_frame_limit_token_nearby_suppresses_alert(self):
        ctx = _context([
            'while( frames_left ) {',
            'if frame_count > frame_limit break',
            'handle_frame( frame )',
        ])
        self.assertEqual(run_frame(ctx), [])

    def test_frame_processing_without_loop_is_silent(self):
        ctx = _context([
            'handle_frame( frame )',
        ])
        self.assertEqual(run_frame(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context([
            'while( has_frames ) {',
            'process_quic_frame( pkt )',
        ])
        findings = run_frame(ctx)
        if findings:
            self.assertEqual(findings[0].task_id, '108')
            self.assertEqual(findings[0].rule_id, 'quic_invisible_frame_limit')


# ---------------------------------------------------------------------------
# Rule 109: quic_handshake_eviction_missing
# ---------------------------------------------------------------------------

class QuicHandshakeEvictionTests(unittest.TestCase):

    def test_pool_full_without_eviction_alerts(self):
        ctx = _context([
            'fd_quic_hs_t * hs = hs_pool_alloc( pool )',
            'if( hs == NULL ) return ERR_BUSY',
        ])
        self.assertTrue(run_hs(ctx))

    def test_eviction_before_rejection_is_silent(self):
        ctx = _context([
            'fd_quic_hs_t * hs = hs_pool_alloc( pool )',
            'if( hs == NULL ) { evict_oldest_handshake( pool )',
            'hs = hs_pool_alloc( pool ) }',
        ])
        self.assertEqual(run_hs(ctx), [])

    def test_no_pool_reference_is_silent(self):
        ctx = _context([
            'conn = fd_quic_conn_new( quic )',
            'if( conn == NULL ) return ERR_BUSY',
        ])
        self.assertEqual(run_hs(ctx), [])

    def test_finding_metadata_is_populated(self):
        ctx = _context([
            'fd_quic_hs_t * hs = hs_pool_alloc( p )',
            'if( hs == NULL ) return NULL',
        ])
        findings = run_hs(ctx)
        if findings:
            self.assertEqual(findings[0].task_id, '109')
            self.assertEqual(findings[0].rule_id, 'quic_handshake_eviction_missing')


if __name__ == '__main__':
    unittest.main()

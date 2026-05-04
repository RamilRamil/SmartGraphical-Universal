"""Unit tests for dataflow-driven C rules 111, 113, 115."""
import unittest

from smartgraphical.adapters.c_base.adapter import build_c_rule_registry
from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.c.c_specific.io_uring_submission_race_funk import (
    run as run_io_uring_race,
)
from smartgraphical.core.rules.c_node.node_specific.keyswitch_atomicity_violation import (
    run as run_keyswitch_atomicity,
)
from smartgraphical.core.rules.c.portable_with_adapter.unsupported_program_id_divergence import (
    run as run_unsupported_program,
)


def _context(statements, dataflow):
    artifact = NormalizedArtifact(path='test.c', language='c', adapter_name='Test')
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name='test_unit', kind='translation_unit')
    function = NormalizedFunction(
        name='target',
        owner='test_unit',
        exploration_statements=list(statements),
    )
    type_entry.functions.append(function)
    model.types.append(type_entry)
    model.findings_data.function_facts['test_unit.target'] = {
        'visibility': 'external',
        'entrypoint': True,
        'statement_count': len(statements),
        'dataflow': dataflow,
    }
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


class IoUringSubmissionRaceTests(unittest.TestCase):

    def test_shared_ring_without_guard_alerts(self):
        ctx = _context(
            ['io_uring_submit( shared_ring )'],
            {
                'io_uring_submit_sites': [{
                    'statement_index': 0,
                    'statement': 'io_uring_submit( shared_ring )',
                    'ring_expr': 'shared_ring',
                    'is_private': False,
                    'is_shared': True,
                    'is_guarded': False,
                }],
                'tile_markers': [{'statement_index': 1, 'statement': 'exec tile path'}],
                'ordered_calls': [],
                'return_error_codes': [],
                'program_guard_sites': [],
            },
        )
        findings = run_io_uring_race(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '111')

    def test_private_ring_is_silent(self):
        ctx = _context(
            ['io_uring_submit( tile->private_ring )'],
            {
                'io_uring_submit_sites': [{
                    'statement_index': 0,
                    'statement': 'io_uring_submit( tile->private_ring )',
                    'ring_expr': 'tile->private_ring',
                    'is_private': True,
                    'is_shared': False,
                    'is_guarded': False,
                }],
                'tile_markers': [],
                'ordered_calls': [],
                'return_error_codes': [],
                'program_guard_sites': [],
            },
        )
        self.assertEqual(run_io_uring_race(ctx), [])


class KeyswitchAtomicityTests(unittest.TestCase):

    def test_update_before_halt_alerts(self):
        ctx = _context(
            ['update_sign_tile( new_key )', 'poh_halt()', 'shred_flush()'],
            {
                'ordered_calls': [
                    {'statement_index': 0, 'call': 'update_sign_tile'},
                    {'statement_index': 1, 'call': 'poh_halt'},
                    {'statement_index': 2, 'call': 'shred_flush'},
                ],
                'io_uring_submit_sites': [],
                'return_error_codes': [],
                'program_guard_sites': [],
                'tile_markers': [],
            },
        )
        findings = run_keyswitch_atomicity(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '113')

    def test_halt_flush_update_is_silent(self):
        ctx = _context(
            ['poh_halt()', 'shred_flush()', 'update_sign_tile( new_key )', 'poh_resume()'],
            {
                'ordered_calls': [
                    {'statement_index': 0, 'call': 'poh_halt'},
                    {'statement_index': 1, 'call': 'shred_flush'},
                    {'statement_index': 2, 'call': 'update_sign_tile'},
                    {'statement_index': 3, 'call': 'poh_resume'},
                ],
                'io_uring_submit_sites': [],
                'return_error_codes': [],
                'program_guard_sites': [],
                'tile_markers': [],
            },
        )
        self.assertEqual(run_keyswitch_atomicity(ctx), [])


class UnsupportedProgramIdDivergenceTests(unittest.TestCase):

    def test_unknown_program_with_wrong_error_alerts(self):
        ctx = _context(
            ['if( !program_exists ) return ERR_NOT_FOUND'],
            {
                'ordered_calls': [],
                'io_uring_submit_sites': [],
                'program_guard_sites': [{
                    'statement_index': 0,
                    'statement': 'if( !program_exists ) return ERR_NOT_FOUND',
                }],
                'return_error_codes': [{
                    'statement_index': 0,
                    'code': 'ERR_NOT_FOUND',
                    'statement': 'if( !program_exists ) return ERR_NOT_FOUND',
                }],
                'tile_markers': [],
            },
        )
        findings = run_unsupported_program(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, '115')

    def test_unknown_program_with_expected_error_is_silent(self):
        ctx = _context(
            ['if( !program_exists ) return ERR_UNSUPPORTED_PROGRAM_ID'],
            {
                'ordered_calls': [],
                'io_uring_submit_sites': [],
                'program_guard_sites': [{
                    'statement_index': 0,
                    'statement': 'if( !program_exists ) return ERR_UNSUPPORTED_PROGRAM_ID',
                }],
                'return_error_codes': [{
                    'statement_index': 0,
                    'code': 'ERR_UNSUPPORTED_PROGRAM_ID',
                    'statement': 'if( !program_exists ) return ERR_UNSUPPORTED_PROGRAM_ID',
                }],
                'tile_markers': [],
            },
        )
        self.assertEqual(run_unsupported_program(ctx), [])


class CRuleRegistryBatch4Tests(unittest.TestCase):

    def test_registry_contains_dataflow_rules(self):
        registry = build_c_rule_registry()
        for task_id in ('111', '113', '115'):
            self.assertIn(task_id, registry)


if __name__ == '__main__':
    unittest.main()

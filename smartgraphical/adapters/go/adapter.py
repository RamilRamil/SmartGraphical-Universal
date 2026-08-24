"""Go adapter: heuristic extraction into NormalizedAuditModel.

Lexer-light parsing (regex + brace balancing) per constitution Principle I.
Rule tasks 1-18: docs/go_language_rules_catalog.json.
"""
from __future__ import annotations

import os
import re
from typing import Iterator, List

from smartgraphical.core.engine import RuleSpec
from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedFunction,
    NormalizedStateEntity,
    NormalizedType,
)
from smartgraphical.core.rules.go.language_rules import (
    run_blank_identifier_index_discard,
    run_build_tag_hidden_security_tests,
    run_closure_loop_variable_capture,
    run_compiler_pragma_linkname,
    run_compiler_pragma_noescape,
    run_compiler_pragma_nosplit,
    run_defer_argument_eager_eval,
    run_external_test_package_blackbox_gap,
    run_multi_param_type_sharing_obscurity,
    run_nil_map_write_panic,
    run_parallel_subtest_loop_capture,
    run_slice_aliasing_sensitive,
    run_sparse_array_initialization,
    run_table_driven_missing_edge_cases,
    run_typed_nil_interface_return,
    run_unbounded_loop_missing_cancel,
    run_value_receiver_mutation_lost,
    run_variable_shadowing_stale_err,
)

_GO_LINE_COMMENT = re.compile(r'//[^\n]*')
_GO_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_FUNC_PLAIN = re.compile(r'\bfunc\s+(\w+)\s*\(')
_FUNC_METHOD = re.compile(r'\bfunc\s*\(\s*(\w+)\s+(\*?)(\w+)\s*\)\s+(\w+)\s*\(')
_STRUCT_TYPE = re.compile(r'\btype\s+(\w+)\s+struct\s*\{')
_CALL_TOKEN = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
_SKIP_CALL = frozenset({
    'if', 'for', 'switch', 'case', 'return', 'make', 'len', 'cap', 'append',
    'copy', 'delete', 'panic', 'recover', 'go', 'defer', 'select', 'func',
})


def _strip_go_comments(source: str) -> str:
    source = _GO_BLOCK_COMMENT.sub(lambda m: '\n' * m.group(0).count('\n'), source)
    return _GO_LINE_COMMENT.sub(lambda m: ' ' * len(m.group(0)), source)


def _extract_body(cleaned: str, open_brace_idx: int) -> tuple[str, int]:
    depth = 0
    i = open_brace_idx
    while i < len(cleaned):
        ch = cleaned[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return cleaned[open_brace_idx + 1 : i], i + 1
        i += 1
    return cleaned[open_brace_idx + 1 :], len(cleaned)


def _params_and_body(cleaned: str, open_paren_idx: int) -> tuple[str, str, int]:
    depth = 0
    j = open_paren_idx
    while j < len(cleaned):
        ch = cleaned[j]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                params = cleaned[open_paren_idx + 1 : j].strip()
                k = j + 1
                while k < len(cleaned) and cleaned[k] in ' \t\r\n':
                    k += 1
                brace = cleaned.find('{', k)
                if brace < 0:
                    return params, '', j + 1
                body, end = _extract_body(cleaned, brace)
                return params, body, end
        j += 1
    return '', '', open_paren_idx + 1


def _iter_functions(cleaned: str) -> Iterator[dict]:
    seen = set()
    for m in _FUNC_METHOD.finditer(cleaned):
        recv_name, star, recv_type, fname = m.groups()
        key = ('method', recv_type, fname)
        if key in seen:
            continue
        seen.add(key)
        paren = cleaned.find('(', m.end() - len(fname) - 1)
        if paren < 0:
            continue
        params, body, _ = _params_and_body(cleaned, paren)
        pref = f'func ({recv_name} {star}{recv_type}) {fname}({params})'
        yield {
            'name': fname,
            'params': params,
            'body': body,
            'pref': pref,
            'value_receiver': star != '*',
            'pointer_receiver': star == '*',
            'receiver_type': recv_type,
            'visibility': 'exported' if fname[:1].isupper() else 'internal',
        }
    for m in _FUNC_PLAIN.finditer(cleaned):
        fname = m.group(1)
        if fname == 'func':
            continue
        key = ('func', fname)
        if key in seen:
            continue
        seen.add(key)
        paren = m.end() - 1
        params, body, _ = _params_and_body(cleaned, paren)
        pref = f'func {fname}({params})'
        yield {
            'name': fname,
            'params': params,
            'body': body,
            'pref': pref,
            'value_receiver': False,
            'pointer_receiver': False,
            'receiver_type': '',
            'visibility': 'exported' if fname[:1].isupper() else 'internal',
        }


def go_split_statements(body: str) -> List[str]:
    stmts = []
    for chunk in body.split(';'):
        part = ' '.join(chunk.split())
        if len(part) > 2:
            stmts.append(part + ';')
    return stmts if stmts else ([' '.join(body.split())[:4000]] if body.strip() else [])


def build_normalized_model(source_path: str, source_text: str) -> NormalizedAuditModel:
    raw = source_text
    cleaned = _strip_go_comments(raw)
    stem = os.path.splitext(os.path.basename(source_path))[0]
    pkg_m = re.search(r'^\s*package\s+(\w+)', raw, re.MULTILINE)
    package_name = pkg_m.group(1) if pkg_m else stem

    artifact = NormalizedArtifact(
        path=source_path,
        language='go',
        adapter_name='GoAdapterV0',
    )
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name=stem or package_name, kind='go_package')

    for sm in _STRUCT_TYPE.finditer(cleaned):
        type_entry.state_entities.append(
            NormalizedStateEntity(name=sm.group(1), owner=stem, kind='struct'),
        )

    name_set = set()
    for fn_info in _iter_functions(cleaned):
        fname = fn_info['name']
        name_set.add(fname)
        stmts = go_split_statements(fn_info['body'])
        function = NormalizedFunction(
            name=fname,
            owner=stem,
            inputs=[fn_info['params'].strip()] if fn_info['params'].strip() else [],
            body=fn_info['body'],
            full_source=fn_info['pref'] + '{' + fn_info['body'] + '}',
            visibility=fn_info['visibility'],
            is_entrypoint=fn_info['visibility'] == 'exported',
            exploration_statements=stmts if stmts else [' '.join(fn_info['body'].split())[:2000]],
        )
        type_entry.functions.append(function)
        fk_key = f'{stem}.{fname}'
        model.exploration_data.function_notes[fk_key] = {
            'statement_count': len(function.exploration_statements),
            'raw_statements': function.exploration_statements,
        }
        model.findings_data.function_facts[fk_key] = {
            'value_receiver': fn_info['value_receiver'],
            'pointer_receiver': fn_info['pointer_receiver'],
            'receiver_type': fn_info['receiver_type'],
            'package_name': package_name,
            'is_test_func': fname.startswith(('Test', 'Benchmark', 'Fuzz')),
        }

    model.types.append(type_entry)
    edges: List[NormalizedCallEdge] = []
    for fn in type_entry.functions:
        for callee in _CALL_TOKEN.findall(fn.body):
            if callee in _SKIP_CALL or callee not in name_set or callee == fn.name:
                continue
            edges.append(
                NormalizedCallEdge(
                    stem,
                    fn.name,
                    stem,
                    callee,
                    'function_to_function',
                    label='intrapackage_call',
                ),
            )
    model.call_edges = edges
    model.rule_groups.setdefault('GoAll', []).extend([str(i) for i in range(1, 19)])
    return model


def build_go_rule_registry() -> dict[str, RuleSpec]:
    entries = [
        ('1', 'sparse_array_initialization', 'Sparse Array Literal With Index Gaps', 'WeirdSyntax', 'medium',
         'Verify wire indices; avoid silent zero-padding.', run_sparse_array_initialization),
        ('2', 'multi_param_type_sharing_obscurity', 'Shared Parameter Type In Signature', 'WeirdSyntax', 'low',
         'Confirm each parameter type in security-sensitive signatures.', run_multi_param_type_sharing_obscurity),
        ('3', 'blank_identifier_index_discard', 'Discarded Range Index', 'WeirdSyntax', 'medium',
         'Bind index when position matters.', run_blank_identifier_index_discard),
        ('4', 'closure_loop_variable_capture', 'Goroutine Loop Variable Capture', 'WeirdSyntax', 'high',
         'Copy loop vars before go func() on pre-1.22 toolchains.', run_closure_loop_variable_capture),
        ('5', 'value_receiver_mutation_lost', 'Value Receiver Mutation Lost', 'WeirdSyntax', 'high',
         'Use pointer receiver for mutating methods.', run_value_receiver_mutation_lost),
        ('6', 'unbounded_loop_missing_cancel', 'Missing Context Cancellation In Loop', 'WeirdSyntax', 'high',
         'Exit on ctx.Done() in worker/event loops.', run_unbounded_loop_missing_cancel),
        ('7', 'nil_map_write_panic', 'Nil Map Write Risk', 'CommonPitfalls', 'high',
         'Initialize maps before write.', run_nil_map_write_panic),
        ('8', 'slice_aliasing_sensitive', 'Slice Aliasing And Append', 'CommonPitfalls', 'high',
         'Copy slices when isolation is required.', run_slice_aliasing_sensitive),
        ('9', 'defer_argument_eager_eval', 'Defer Eager Argument Evaluation', 'CommonPitfalls', 'medium',
         'Wrap deferred metrics in a closure.', run_defer_argument_eager_eval),
        ('10', 'typed_nil_interface_return', 'Typed Nil error Return', 'CommonPitfalls', 'high',
         'Return bare nil on success.', run_typed_nil_interface_return),
        ('11', 'variable_shadowing_stale_err', 'err Shadowing Or Stale Wrap', 'CommonPitfalls', 'medium',
         'Run go vet -shadow; wrap correct err.', run_variable_shadowing_stale_err),
        ('12', 'parallel_subtest_loop_capture', 'Parallel Subtest Loop Capture', 'TestingSurface', 'medium',
         'Use tc := tc with t.Parallel pre-1.22.', run_parallel_subtest_loop_capture),
        ('13', 'build_tag_hidden_security_tests', 'Build Tag Gated Tests', 'TestingSurface', 'medium',
         'Run CI with required -tags.', run_build_tag_hidden_security_tests),
        ('14', 'table_driven_missing_edge_cases', 'Table Tests Missing Edge Cases', 'TestingSurface', 'low',
         'Add error and boundary rows to tables.', run_table_driven_missing_edge_cases),
        ('15', 'external_test_package_blackbox_gap', 'External Test Package Only', 'TestingSurface', 'low',
         'Add white-box tests for internals.', run_external_test_package_blackbox_gap),
        ('16', 'compiler_pragma_noescape', '//go:noescape Present', 'CompilerPragmas', 'high',
         'Review escape analysis assumptions.', run_compiler_pragma_noescape),
        ('17', 'compiler_pragma_nosplit', '//go:nosplit Present', 'CompilerPragmas', 'high',
         'Ensure bounded stack use.', run_compiler_pragma_nosplit),
        ('18', 'compiler_pragma_linkname', '//go:linkname Present', 'CompilerPragmas', 'high',
         'Scrutinize cross-package unexported access.', run_compiler_pragma_linkname),
    ]
    registry = {}
    for task_id, slug, title, category, confidence, hint, runner in entries:
        registry[task_id] = RuleSpec(
            task_id,
            int(task_id),
            slug,
            title,
            category,
            'go',
            confidence,
            hint,
            runner,
        )
    return registry


class GoAdapterV0:
    def parse_source(self, source_path: str, *, expand_local_imports: bool = True):
        del expand_local_imports
        with open(source_path, 'r', errors='replace') as handle:
            text = handle.read()
        model = build_normalized_model(source_path, text)
        return AnalysisContext(
            path=source_path,
            language='go',
            reader=None,
            lines=text.splitlines(),
            unified_code=text,
            rets=[],
            hierarchy={},
            high_connections=[],
            normalized_model=model,
        )

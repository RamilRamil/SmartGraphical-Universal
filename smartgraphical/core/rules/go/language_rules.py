"""Go language audit heuristics (tasks 1-18).

Derived from docs/go_language_rules_catalog.json (Sigma Prime Go for Security
Auditors Part 1). Shallow grep-grade signals only; not a substitute for go vet
or the race detector.
"""

from __future__ import annotations

import re

from smartgraphical.core.engine import make_findings

_SPARSE_ARRAY = re.compile(r'\[\.\.\.\][\w]*\{[^}]*\d+\s*:')
_MULTI_PARAM_SHARED = re.compile(
    r'func\s+\w+\s*\(([^)]{8,})\)',
)
_FOR_BLANK_INDEX = re.compile(r'\bfor\s+_\s*,\s*\w+\s*:=\s*range\b')
_GO_IN_LOOP = re.compile(r'\bfor\b[^{]*\{[^}]*\bgo\s+func\s*\(', re.DOTALL)
_LOOP_COPY_GUARD = re.compile(r'\b(?:\w+)\s*:=\s*(?:\w+)\s*\n[^}]*\bgo\s+func')
_BARE_FOR = re.compile(r'\bfor\s*\{')
_CTX_DONE = re.compile(r'ctx\.Done\s*\(\)|context\.Done\s*\(\)|<-ctx\.Done')
_MAP_FIELD_WRITE = re.compile(r'\.\w+\s*\[[^\]]+\]\s*=')
_STRUCT_MAP_FIELD = re.compile(r'\bmap\s*\[[^\]]+\]')
_MAKE_MAP = re.compile(r'\bmake\s*\(\s*map\b|\bmap\s*\[[^\]]+\]\s*\{')
_SLICE_SUB = re.compile(r'\[\s*\d+\s*:\s*\d+\s*\]')
_APPEND_AFTER_SLICE = re.compile(
    r'\[\s*\d+\s*:\s*\d+\s*\][^;]{0,120}\bappend\s*\(',
    re.DOTALL,
)
_DEFER_CALL = re.compile(r'\bdefer\s+[\w.]+\([^)]*\)')
_DEFER_EAGER = re.compile(
    r'\bdefer\s+\w+\([^)]*(?:time\.Since|len\s*\(|cap\s*\()',
)
_TYPED_NIL_RETURN = re.compile(
    r'func\s+\w+\s*\([^)]*\)\s*error\s*\{[^}]*var\s+\w+\s+\*[\w.]+\s*=\s*nil[^}]*return\s+\w+',
    re.DOTALL,
)
_SHADOW_ERR = re.compile(r'\bif\s+[^{]*\berr\s*:=')
_FMT_WRAP_ERR = re.compile(r'fmt\.Errorf\s*\([^)]*%w[^)]*,\s*err\s*\)')
_PARALLEL_SUB = re.compile(r'\bt\.Parallel\s*\(\s*\)')
_TC_COPY = re.compile(r'\b\w+\s*:=\s*\w+\s*\n[^}]*t\.Run\s*\(')
_BUILD_TAG = re.compile(r'//go:build\s+\S+')
_TABLE_TEST = re.compile(r'tests\s*:=\s*\[\]struct\s*\{')
_WANT_ERR = re.compile(r'\bwantErr\b|\bexpectErr\b|errors?\s+\w+\s+\w+')
_PKG_TEST_SUFFIX = re.compile(r'^\s*package\s+\w+_test\b', re.MULTILINE)
_NOESCAPE = re.compile(r'//go:noescape\b')
_NOSPLIT = re.compile(r'//go:nosplit\b')
_LINKNAME = re.compile(r'//go:linkname\b')
_VALUE_RECV_MUT = re.compile(r'\bs\.\w+\s*=')


def _file_meta(task_id, slug, title, category, confidence, hint):
    return dict(
        task_id=task_id,
        legacy_code=int(task_id),
        slug=slug,
        title=title,
        category=category,
        portability='go',
        confidence=confidence,
        remediation_hint=hint,
    )


def _unified(context):
    return getattr(context, 'unified_code', '') or ''


def run_sparse_array_initialization(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '1', 'sparse_array_initialization',
        'Sparse Composite Literal With Index Gaps',
        'WeirdSyntax', 'medium',
        'Verify wire-format indices; avoid silent zero-padding in packed arrays.',
    )
    alerts = []
    for m in _SPARSE_ARRAY.finditer(unified):
        alerts.append({'code': 1, 'message': f'Sparse array literal with index key: {m.group(0)[:100]}'})
    return make_findings(alerts, model, **meta)


def run_multi_param_type_sharing_obscurity(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '2', 'multi_param_type_sharing_obscurity',
        'Shared Type Declaration Hides Parameter Kinds',
        'WeirdSyntax', 'low',
        'Re-read signatures on verify/compare helpers with shared parameter types.',
    )
    alerts = []
    for m in _MULTI_PARAM_SHARED.finditer(unified):
        params = m.group(1)
        if params.count(',') >= 2 and len(re.findall(r'\w+\s*,', params)) >= 2:
            type_tail = re.search(r'(\w+(?:\[\])?)\s*\)\s*$', params + ')')
            if type_tail and params.count(type_tail.group(1)) >= 1:
                alerts.append({
                    'code': 2,
                    'message': f'Function params share one type ({type_tail.group(1)}); confirm intent.',
                })
    return make_findings(alerts, model, **meta)


def run_blank_identifier_index_discard(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '3', 'blank_identifier_index_discard',
        'Loop Index Discarded Where Position May Matter',
        'WeirdSyntax', 'medium',
        'Bind range index when ordering or position affects correctness.',
    )
    alerts = []
    for m in _FOR_BLANK_INDEX.finditer(unified):
        tail = unified[m.end() : m.end() + 400]
        if re.search(r'(?i)\b(?:index|ordinal|position|parity|first|last)\b', tail):
            alerts.append({'code': 3, 'message': 'for _, x := range with positional hints in body; check index use.'})
    return make_findings(alerts, model, **meta)


def run_closure_loop_variable_capture(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '4', 'closure_loop_variable_capture',
        'Goroutine Captures Loop Variable By Reference',
        'WeirdSyntax', 'high',
        'Copy loop variable per iteration (i := i) on pre-Go-1.22 codebases.',
    )
    alerts = []
    if _GO_IN_LOOP.search(unified) and not _LOOP_COPY_GUARD.search(unified):
        alerts.append({
            'code': 4,
            'message': 'go func() inside for loop without obvious per-iteration copy (pre-1.22 hazard).',
        })
    return make_findings(alerts, model, **meta)


def run_value_receiver_mutation_lost(context):
    model = context.normalized_model
    alerts = []
    meta = _file_meta(
        '5', 'value_receiver_mutation_lost',
        'Mutating Method Uses Value Receiver',
        'WeirdSyntax', 'high',
        'Use pointer receiver (*T) when mutating receiver fields or locks.',
    )
    for t in getattr(model, 'types', []) or []:
        for fn in getattr(t, 'functions', []) or []:
            facts = (getattr(model, 'findings_data', None) or None)
            fk = {}
            if facts:
                fk = facts.function_facts.get(f'{t.name}.{fn.name}', {})
            if not fk.get('value_receiver'):
                continue
            body = fn.body or ''
            if _VALUE_RECV_MUT.search(body) or re.search(r'\bs\.(?:Lock|Unlock|RLock|RUnlock)\s*\(', body):
                alerts.append({
                    'code': 5,
                    'message': f'Method `{fn.name}` uses value receiver but mutates receiver state.',
                })
    return make_findings(alerts, model, **meta)


def run_unbounded_loop_missing_cancel(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '6', 'unbounded_loop_missing_cancel',
        'Bare for Loop Without Context Cancellation',
        'WeirdSyntax', 'high',
        'Add select branch on ctx.Done() for event loops and workers.',
    )
    alerts = []
    for m in _BARE_FOR.finditer(unified):
        window = unified[m.start() : m.start() + 800]
        if 'select' in window and not _CTX_DONE.search(window):
            alerts.append({'code': 6, 'message': 'for { select { ... } } without ctx.Done() cancellation path.'})
        elif 'select' not in window:
            alerts.append({'code': 6, 'message': 'Unbounded for {} loop; trace shutdown/exit paths.'})
    return make_findings(alerts, model, **meta)


def run_nil_map_write_panic(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '7', 'nil_map_write_panic',
        'Write To Nil Map Field Without Constructor Init',
        'CommonPitfalls', 'high',
        'Initialize map fields in constructors before first write.',
    )
    alerts = []
    if _STRUCT_MAP_FIELD.search(unified) and _MAP_FIELD_WRITE.search(unified):
        if not _MAKE_MAP.search(unified):
            alerts.append({'code': 7, 'message': 'Map field write without visible make/map literal initialization.'})
        else:
            for m in _MAP_FIELD_WRITE.finditer(unified):
                prefix = unified[max(0, m.start() - 200) : m.start()]
                if 'make(map' not in prefix and 'map[' not in prefix.split('func')[-1][:120]:
                    alerts.append({'code': 7, 'message': f'Possible nil map write: {m.group(0)[:80]}'})
                    break
    return make_findings(alerts, model, **meta)


def run_slice_aliasing_sensitive(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '8', 'slice_aliasing_sensitive',
        'Slice Sub-range Shares Backing Array',
        'CommonPitfalls', 'high',
        'Copy slices when isolation is required before append or mutation.',
    )
    alerts = []
    if _SLICE_SUB.search(unified) and (
        _APPEND_AFTER_SLICE.search(unified) or re.search(r'\[\s*\d+\s*:\s*\d+\s*\][^;]{0,80}\[\d+\]\s*=', unified)
    ):
        alerts.append({'code': 8, 'message': 'Slice sub-range with append or indexed mutation (aliasing risk).'})
    return make_findings(alerts, model, **meta)


def run_defer_argument_eager_eval(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '9', 'defer_argument_eager_eval',
        'Defer Evaluates Arguments At Registration Time',
        'CommonPitfalls', 'medium',
        'Wrap deferred logging/metrics in func() { ... }().',
    )
    alerts = []
    for m in _DEFER_EAGER.finditer(unified):
        if 'func()' in unified[max(0, m.start() - 20) : m.start()]:
            continue
        alerts.append({'code': 9, 'message': f'Defer may evaluate args early: {m.group(0)[:90]}'})
    return make_findings(alerts, model, **meta)


def run_typed_nil_interface_return(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '10', 'typed_nil_interface_return',
        'Typed Nil Pointer Returned As error Interface',
        'CommonPitfalls', 'high',
        'Return bare nil on success paths through error interface.',
    )
    alerts = []
    if _TYPED_NIL_RETURN.search(unified.replace('\n', ' ')):
        alerts.append({'code': 10, 'message': 'Function may return typed nil pointer as error (err != nil trap).'})
    elif re.search(r'var\s+\w+\s+\*[\w.]+\s*=\s*nil\s*\n[^}]*return\s+\w+', unified):
        fn_chunk = re.search(r'func\s+\w+[^{]+\{[^}]*var\s+\w+\s+\*[\w.]+\s*=\s*nil[^}]*return\s+\w+', unified, re.DOTALL)
        if fn_chunk and 'error' in fn_chunk.group(0):
            alerts.append({'code': 10, 'message': 'Typed nil error variable returned through error interface.'})
    return make_findings(alerts, model, **meta)


def run_variable_shadowing_stale_err(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '11', 'variable_shadowing_stale_err',
        'err Shadowing Or Stale err In fmt.Errorf Wrap',
        'CommonPitfalls', 'medium',
        'Run go vet -shadow; wrap the err from the failing branch only.',
    )
    alerts = []
    if _SHADOW_ERR.search(unified):
        alerts.append({'code': 11, 'message': 'if block uses err := (possible shadowing of outer err).'})
    for m in _FMT_WRAP_ERR.finditer(unified):
        before = unified[max(0, m.start() - 250) : m.start()]
        if '.(' in before and 'err =' not in before.split('.(')[-1][:80]:
            alerts.append({'code': 11, 'message': 'fmt.Errorf wraps err after type assertion failure (stale err risk).'})
            break
    return make_findings(alerts, model, **meta)


def run_parallel_subtest_loop_capture(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '12', 'parallel_subtest_loop_capture',
        'Parallel Subtests Without Per-Case Loop Copy',
        'TestingSurface', 'medium',
        'Add tc := tc before t.Run when using t.Parallel (pre-1.22).',
    )
    alerts = []
    if _PARALLEL_SUB.search(unified) and re.search(r'for\s*,\s*\w+\s*:=\s*range', unified):
        if not _TC_COPY.search(unified):
            alerts.append({'code': 12, 'message': 't.Parallel in range loop without tc := tc copy heuristic.'})
    return make_findings(alerts, model, **meta)


def run_build_tag_hidden_security_tests(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '13', 'build_tag_hidden_security_tests',
        'Tests Gated By Build Tags',
        'TestingSurface', 'medium',
        'Ensure CI runs go test with required -tags for security tests.',
    )
    alerts = []
    if _BUILD_TAG.search(unified) and 'Test' in unified:
        alerts.append({'code': 13, 'message': 'File uses //go:build tag; confirm CI enables matching -tags.'})
    return make_findings(alerts, model, **meta)


def run_table_driven_missing_edge_cases(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '14', 'table_driven_missing_edge_cases',
        'Table-Driven Tests May Omit Error And Boundary Rows',
        'TestingSurface', 'low',
        'Add malformed, empty, max, and error cases to test tables.',
    )
    alerts = []
    if _TABLE_TEST.search(unified) and not _WANT_ERR.search(unified):
        alerts.append({'code': 14, 'message': 'Table-driven tests struct lacks wantErr/error column heuristic.'})
    return make_findings(alerts, model, **meta)


def run_external_test_package_blackbox_gap(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '15', 'external_test_package_blackbox_gap',
        'Black-Box Test Package Only',
        'TestingSurface', 'low',
        'Add same-package tests for unexported invariant coverage.',
    )
    alerts = []
    if _PKG_TEST_SUFFIX.search(unified) and 'Test' in unified:
        alerts.append({'code': 15, 'message': 'package foo_test cannot access unexported symbols (black-box only).'})
    return make_findings(alerts, model, **meta)


def run_compiler_pragma_noescape(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '16', 'compiler_pragma_noescape',
        'Unsafe //go:noescape Annotation',
        'CompilerPragmas', 'high',
        'Verify pointer lifetimes; incorrect noescape risks use-after-free.',
    )
    alerts = []
    if _NOESCAPE.search(unified):
        alerts.append({'code': 16, 'message': '//go:noescape present; review escape analysis assumptions.'})
    return make_findings(alerts, model, **meta)


def run_compiler_pragma_nosplit(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '17', 'compiler_pragma_nosplit',
        'Unsafe //go:nosplit Annotation',
        'CompilerPragmas', 'high',
        'Ensure stack use is bounded; nosplit prevents stack growth.',
    )
    alerts = []
    if _NOSPLIT.search(unified):
        alerts.append({'code': 17, 'message': '//go:nosplit present; verify bounded stack/recursion depth.'})
    return make_findings(alerts, model, **meta)


def run_compiler_pragma_linkname(context):
    model = context.normalized_model
    unified = _unified(context)
    meta = _file_meta(
        '18', 'compiler_pragma_linkname',
        '//go:linkname Breaks Encapsulation',
        'CompilerPragmas', 'high',
        'Avoid linkname unless accessing runtime internals is unavoidable.',
    )
    alerts = []
    if _LINKNAME.search(unified):
        alerts.append({'code': 18, 'message': '//go:linkname imports unexported symbols across packages.'})
    return make_findings(alerts, model, **meta)

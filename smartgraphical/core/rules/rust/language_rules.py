"""Rust 1.x / Edition-agnostic heuristic rules (tasks 209-223).

Includes Base Azul review helpers (217-223): shallow grep-grade signals only.

Requires adapter-filled AnalysisContext(unified_code, lines) and NormalizedAuditModel.functions.
Heavy semantic rules (borrowck, MIR) intentionally stay shallow.
"""

from __future__ import annotations

import re

from smartgraphical.core.engine import make_findings

_CFG_TEST_NEAR_FN = re.compile(
    r'#\[\s*cfg\s*\(\s*(?:[^\)]*\b)?test[^\)]*\)\s*\]',
    re.MULTILINE,
)
_UNSAFE_BLOCK = re.compile(r'\bunsafe\s*\{|\#\[\s*unsafe\b')
_STATIC_MUT_DECL = re.compile(r'\bstatic\s+mut\s+([A-Za-z_][a-zA-Z0-9_]*)\s*[:=]', re.MULTILINE)
_THREADS = re.compile(
    r'\b(?:std\s*::\s*)?thread\s*::\s*spawn|\.spawn\s*\(|rayon\s*::|crossbeam(::|\s*\.\s*)',
)
_INTERIOR_CELL = re.compile(r'\b(?:RefCell|Cell|UnsafeCell)\s*<')
_PUB_PANICKY = re.compile(r'\b(?:panic\s*!\s*\(|\.unwrap\s*\(\s*\)|\.expect\s*\()', re.MULTILINE)
_LOOP_HEAD = re.compile(r'\b(?:for|while)\b')
_ARC_RC = re.compile(r'\b(?:Arc|Rc)\s*(?:<|::)')
_OLD_ASYNC_FN_SHAPE = re.compile(
    r'\b(?:dyn\s+)?Fn(?:Once)?\([^)]*\)\s*\+\s*|FnMut\s*\([^)]*\).*?Future|dyn\s+Fn\([^)]+\)[^:{]*\{[^}]*\bawait\b',
    re.DOTALL,
)
_NO_STD_HDR = re.compile(r'#!\[\s*no_std\s*\]', re.MULTILINE)
_STD_PATH = re.compile(r'\bstd\s*::')
_CFG_STD = re.compile(r'#\[\s*cfg[^\]]*\b(?:feature\s*=\s*"std")\b[^\]]*\]', re.MULTILINE)
_TEMP_TAIL_REF = re.compile(
    r'\blet\s+[a-zA-Z_][\w]*\s*=\s*&+(?:mut\s+)?(?:[a-zA-Z_][\w]*)\s*\(',
)
_STATE_DERIV_HINT = re.compile(
    r'(?i)\b(?:merkle|state_root|trie|commitment|derivation|witness|storage_root)\b',
)
_HASH_COLL_STD = re.compile(r'\b(?:HashMap|HashSet)\s*(?:<|::)')
_SPAWN_SITE = re.compile(r'\b(?:tokio\s*::)?task\s*::\s*spawn\b|\btokio\s*::\s*spawn\b')
_PANIC_OPS_NEAR_SPAWN = re.compile(r'\.unwrap\s*\(|\.expect\s*\(|panic!\s*\(')
_SERDE_FLATTEN = re.compile(r'#\[\s*serde\s*\(\s*flatten\s*\)\s*\]')
_SERDE_TRAIT_USE = re.compile(r'\b(?:Serialize|Deserialize)\b')
_FORK_CHOICE_TOKEN = re.compile(r'\bfork_choice\b|\bForkChoice\b')
_GAS_LIMIT = re.compile(r'(?i)gas_limit')
_BATCH_HINT = re.compile(r'(?i)batcher|\bbatch\b')
_PROPOSAL_HINT = re.compile(r'(?i)\bproposal\b')
_U64_RANGE_PAIR = re.compile(
    r'(?i)(?:\b(?:start|begin)\s*:\s*u64\b.*\b(?:end|finish|stop)\s*:\s*u64\b|\b(?:end|finish|stop)\s*:\s*u64\b.*\b(?:start|begin)\s*:\s*u64\b)',
    re.DOTALL,
)
_RANGE_GUARD = re.compile(r'checked_sub\s*\(|ensure!\s*\(|debug_assert!\s*\(|saturating_sub\s*\(')
_PANIC_WITH_ERROR = re.compile(r'\bpanic_with_error\s*!')
_PLAIN_PANIC = re.compile(r'\bpanic!\s*\(')


def _fn_precedes_cfg_test(full_source_code: str, fn_name: str) -> bool:
    """Skip pub API when preceding attributes include cfg(test)."""
    m = re.search(
        rf'\bpub\s*(?:\([^)]*\)\s*)?fn\s+{re.escape(fn_name)}\s*\(',
        full_source_code,
        re.MULTILINE,
    )
    if not m:
        return False
    prefix = full_source_code[: m.start()][-500:]
    return bool(_CFG_TEST_NEAR_FN.search(prefix))


def _lines_near_cfg_test(lines: list[str], idx: int, lookback: int = 42) -> bool:
    snippet = '\n'.join(lines[max(0, idx - lookback) : idx + 1])
    return bool(re.search(r'#\s*\[\s*cfg\s*\([^\)]*test', snippet))


def _unsafe_block_has_safety_comment(lines: list[str], start_line_idx: int) -> bool:
    snippet = '\n'.join(lines[max(0, start_line_idx - 15) : start_line_idx + 1])
    return bool(re.search(r'(?://[!/]?\s*SAFETY:|///\s*SAFETY:)', snippet, re.IGNORECASE))


def run_undocumented_unsafe_block(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    raw_lines = unified.splitlines()
    alerts = []
    meta = dict(
        task_id='209',
        legacy_code=209,
        slug='undocumented_unsafe_block',
        title='Unsafe Block or Attribute Without SAFETY Commentary',
        category='memory_safety',
        portability='rust',
        confidence='medium',
        remediation_hint='Precede every unsafe {} or #[unsafe(...)] site with `// SAFETY:` explaining upheld invariants.',
    )
    for i, raw in enumerate(raw_lines):
        stripped = raw.split('//')[0]
        if not _UNSAFE_BLOCK.search(stripped):
            continue
        if _unsafe_block_has_safety_comment(raw_lines, i):
            continue
        if _lines_near_cfg_test(raw_lines, i):
            continue
        alerts.append({'code': 209, 'message': f'Undocumented unsafe near line {i + 1}: {raw.strip()[:120]}'})
    return make_findings(alerts, model, **meta)


def run_static_mut_ref_access(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='210',
        legacy_code=210,
        slug='static_mut_ref_access',
        title='Borrow of static mut Variable',
        category='memory_safety',
        portability='rust',
        confidence='high',
        remediation_hint='Prefer interior sync types (LazyLock, Mutex, atomics); avoid referencing static mut.',
    )
    names = set(_STATIC_MUT_DECL.findall(unified))
    for name in names:
        needle = rf'&(mut\s+)?{re.escape(name)}\b'
        if re.search(needle, unified):
            alerts.append(
                {'code': 210, 'message': f'Possible reference to static mut `{name}` in source.'},
            )
    return make_findings(alerts, model, **meta)


def run_interior_mutability_sync_violation(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '').replace('\n', ' ')
    alerts = []
    meta = dict(
        task_id='211',
        legacy_code=211,
        slug='interior_mutability_sync_violation',
        title='Interior Mutability Type Near Thread-Spawning Constructs',
        category='concurrency',
        portability='rust',
        confidence='low',
        remediation_hint='Verify Sync when sharing RefCell/Cell across threads or use Mutex/RwLock.',
    )
    if not _THREADS.search(unified):
        return make_findings([], model, **meta)
    if not _INTERIOR_CELL.search(unified):
        return make_findings([], model, **meta)
    alerts.append(
        {
            'code': 211,
            'message': (
                'File mixes RefCell/Cell/UnsafeCell with thread spawn or Rayon-style APIs '
                '(heuristic; audit Send/Sync).'
            ),
        },
    )
    return make_findings(alerts, model, **meta)


def run_unprotected_panic_in_public_api(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='212',
        legacy_code=212,
        slug='unprotected_panic_in_public_api',
        title='panic!, unwrap(), or expect() on Public Callable',
        category='robustness',
        portability='rust',
        confidence='medium',
        remediation_hint='Return Result types from public helpers or document unwrap invariants loudly.',
    )
    for t in getattr(model, 'types', []) or []:
        for fn in getattr(t, 'functions', []) or []:
            if getattr(fn, 'visibility', '') not in {'external', 'crate'}:
                continue
            if _fn_precedes_cfg_test(unified, fn.name):
                continue
            body = fn.body or ''
            if not _PUB_PANICKY.search(body):
                continue
            alerts.append({
                'code': 212,
                'message': (
                    f"Public `{t.name}.{fn.name}` contains unwrap/expect/panic! without cfg(test) guard."
                ),
            })
    return make_findings(alerts, model, **meta)


def run_redundant_arc_clone_in_loop(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='213',
        legacy_code=213,
        slug='redundant_arc_clone_in_loop',
        title='Potential Arc/Rc Clone Inside Simple Loop Pattern',
        category='performance',
        portability='rust',
        confidence='low',
        remediation_hint='Clone pointer once before loop or pass &T if sharing read-only.',
    )
    for t in getattr(model, 'types', []) or []:
        for fn in getattr(t, 'functions', []) or []:
            body = getattr(fn, 'body', '') or ''
            if not _LOOP_HEAD.search(body):
                continue
            if '.clone()' not in body:
                continue
            if not _ARC_RC.search(body):
                continue
            for_pos_cands = []
            ix = body.find('for ')
            if ix >= 0:
                for_pos_cands.append(ix)
            iw = body.find('while ')
            if iw >= 0:
                for_pos_cands.append(iw)
            if not for_pos_cands:
                continue
            anchor = min(for_pos_cands)
            clone_pos = body.find('.clone()', anchor)
            if clone_pos >= 0:
                alerts.append(
                    {
                        'code': 213,
                        'message': f'`{t.name}.{fn.name}` clones Arc/Rc after loop head (positional heuristic).',
                    },
                )
    return make_findings(alerts, model, **meta)


def run_missing_async_fn_trait_bound(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='214',
        legacy_code=214,
        slug='missing_async_fn_trait_bound',
        title='Async Closure Pattern May Prefer AsyncFn* Traits',
        category='maintainability',
        portability='rust',
        confidence='low',
        remediation_hint=(
            'On Rust 1.85+, prefer AsyncFn/AsyncFnMut/AsyncFnOnce where async closures '
            'replace dyn Fn(...) -> Fut patterns.'
        ),
    )
    if 'AsyncFn' in unified.replace(' ', ''):
        return make_findings([], model, **meta)
    if _OLD_ASYNC_FN_SHAPE.search(unified):
        alerts.append({'code': 214, 'message': 'Async-friendly Fn-returning Future pattern spotted; review AsyncFn migration.'})
    return make_findings(alerts, model, **meta)


def run_temporary_lifetime_extension_confusion(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='215',
        legacy_code=215,
        slug='temporary_lifetime_extension_confusion',
        title='Suspect Borrow of Temporary Returned Value',
        category='lifetime',
        portability='rust',
        confidence='low',
        remediation_hint=(
            'After Rust temporary scope tweaks, hoist temporaries before borrowing their fields.'
        ),
    )
    for m in _TEMP_TAIL_REF.finditer(unified):
        text = m.group(0).replace('\n', ' ')
        if 'panic' in text:
            continue
        alerts.append(
            {'code': 215, 'message': f'Possible borrowed temporary pattern: `{text.strip()[:100]}`'},
        )
    return make_findings(alerts[:6], model, **meta)


def run_forbidden_std_usage(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='216',
        legacy_code=216,
        slug='forbidden_std_usage',
        title='std:: Usage Under Crate no_std Banner',
        category='determinism',
        portability='rust',
        confidence='high',
        remediation_hint='Use core:: or cfg-gated std helpers when building no_std / wasm crates.',
    )
    if not _NO_STD_HDR.search(unified[:8000]):
        return make_findings([], model, **meta)
    for line_no, line in enumerate(unified.splitlines(), start=1):
        if _CFG_STD.search(line):
            continue
        if '//' in line:
            stmt = line.split('//')[0].strip()
        else:
            stmt = line.strip()
        if not stmt or stmt.startswith('///'):
            continue
        if not _STD_PATH.search(stmt):
            continue
        if stmt.strip().startswith('#['):
            continue
        alerts.append({'code': 216, 'message': f'Line {line_no}: `{stmt.strip()[:120]}` touches std while crate is no_std.'})
    # cap noise when many deps re-export std
    return make_findings(alerts[:30], model, **meta)


def run_non_deterministic_state_root(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='217',
        legacy_code=217,
        slug='non_deterministic_state_root',
        title='Non-deterministic Collections Near State Derivation',
        category='determinism',
        portability='rust',
        confidence='low',
        remediation_hint='Prefer BTreeMap or deterministic key ordering before hashing state or commitments.',
    )
    if _STATE_DERIV_HINT.search(unified) and _HASH_COLL_STD.search(unified):
        alerts.append(
            {
                'code': 217,
                'message': 'HashMap/HashSet near state-root/commitment hints; verify deterministic iteration.',
            },
        )
    return make_findings(alerts, model, **meta)


def run_async_boundary_panic_leak(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    raw_lines = unified.splitlines()
    alerts = []
    meta = dict(
        task_id='218',
        legacy_code=218,
        slug='async_boundary_panic_leak',
        title='Panic/unwrap Near Async Spawn Boundary',
        category='concurrency',
        portability='rust',
        confidence='low',
        remediation_hint='Bubble Result out of spawned tasks or isolate failures without partial commits.',
    )
    for i, raw in enumerate(raw_lines):
        stmt = raw.split('//')[0]
        if not _SPAWN_SITE.search(stmt):
            continue
        if _lines_near_cfg_test(raw_lines, i):
            continue
        window_stmt = '\n'.join(x.split('//')[0] for x in raw_lines[i : min(len(raw_lines), i + 160)])
        if _PANIC_OPS_NEAR_SPAWN.search(window_stmt):
            alerts.append(
                {
                    'code': 218,
                    'message': f'Spawn site near line {i + 1} shares scope with unwrap/expect/panic! (review async boundaries).',
                },
            )
        if len(alerts) >= 8:
            break
    return make_findings(alerts, model, **meta)


def run_serde_binary_codec_mismatch(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='219',
        legacy_code=219,
        slug='serde_binary_codec_mismatch',
        title='serde(flatten) With Serialize/Deserialize Present',
        category='serialization',
        portability='rust',
        confidence='low',
        remediation_hint='Compare canonical layouts across CL/EL crates; avoid implicit reorder hazards.',
    )
    if _SERDE_FLATTEN.search(unified) and _SERDE_TRAIT_USE.search(unified):
        alerts.append(
            {
                'code': 219,
                'message': 'serde(flatten) detected with Serialize/Deserialize; audit CL vs EL binary layouts.',
            },
        )
    return make_findings(alerts, model, **meta)


def run_divergent_fork_choice_assumptions(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='220',
        legacy_code=220,
        slug='divergent_fork_choice_assumptions',
        title='Fork-choice Logic Present',
        category='consensus',
        portability='rust',
        confidence='low',
        remediation_hint='Cross-check fork-choice thresholds vs paired EL/CL crates for identical constants.',
    )
    if _FORK_CHOICE_TOKEN.search(unified):
        alerts.append(
            {
                'code': 220,
                'message': 'Fork-choice symbols detected; manually verify EL/CL finality distance constants stay aligned.',
            },
        )
    return make_findings(alerts, model, **meta)


def run_gas_limit_cl_el_mismatch(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='221',
        legacy_code=221,
        slug='gas_limit_cl_el_mismatch',
        title='Gas Limit Near Batching Context',
        category='execution',
        portability='rust',
        confidence='low',
        remediation_hint='Ensure batcher simulations rebuild the same Env/gas limits as the executor.',
    )
    if _GAS_LIMIT.search(unified) and _BATCH_HINT.search(unified):
        alerts.append(
            {
                'code': 221,
                'message': 'gas_limit co-located with batch/batcher hints; verify EL parity on limits.',
            },
        )
    return make_findings(alerts, model, **meta)


def run_unbounded_proposal_range(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='222',
        legacy_code=222,
        slug='unbounded_proposal_range',
        title='Proposal u64 Range Without Obvious Guards',
        category='logic',
        portability='rust',
        confidence='low',
        remediation_hint='Validate start/end ordering and max span before allocating replay work.',
    )
    if not _PROPOSAL_HINT.search(unified):
        return make_findings([], model, **meta)
    if not _U64_RANGE_PAIR.search(unified):
        return make_findings([], model, **meta)
    if _RANGE_GUARD.search(unified):
        return make_findings([], model, **meta)
    alerts.append(
        {
            'code': 222,
            'message': 'Proposal-like u64 window without checked_sub/ensure-style guards spotted.',
        },
    )
    return make_findings(alerts, model, **meta)


def run_tee_side_channel_via_panic(context):
    model = context.normalized_model
    unified = getattr(context, 'unified_code', '') or ''
    alerts = []
    meta = dict(
        task_id='223',
        legacy_code=223,
        slug='tee_side_channel_via_panic',
        title='Mixed panic_with_error! and panic! Paths',
        category='side_channels',
        portability='rust',
        confidence='low',
        remediation_hint='Normalize signing errors to uniform branches to reduce timing leakage.',
    )
    probe = '\n'.join(line.split('//')[0] for line in unified.splitlines())
    if _PANIC_WITH_ERROR.search(probe) and _PLAIN_PANIC.search(probe):
        alerts.append(
            {
                'code': 223,
                'message': 'Both panic_with_error! and panic! appear; review constant-time/uniform error handling.',
            },
        )
    return make_findings(alerts, model, **meta)

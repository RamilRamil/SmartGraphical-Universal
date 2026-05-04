"""Eight Soroban static checks (tasks 201-208).

Each runner inspects Adapter-built function_facts keyed as `<stem>.<fn>`.
"""

from __future__ import annotations

import re

from smartgraphical.core.engine import make_findings


def _entries(model):
    for type_entry in model.types:
        for function in getattr(type_entry, 'functions', []) or []:
            key = f'{type_entry.name}.{function.name}'
            yield type_entry.name, function, key


def run_missing_auth_check(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='201',
        legacy_code=201,
        slug='missing_auth_check',
        title='Missing Authorization on Public Entry That Mutates State',
        category='authorization',
        portability='rust_stellar',
        confidence='medium',
        remediation_hint='Call require_auth or require_auth_for_args before mutating privilege-bearing storage.',
    )
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if not facts.get('within_contractimpl'):
            continue
        if not function.is_entrypoint:
            continue
        if not facts.get('mutates_ledger_like'):
            continue
        if facts.get('calls_require_auth'):
            continue
        alerts.append({
            'code': 201,
            'message': (
                f"Public entry '{tname}.{function.name}' mutates ledger storage without "
                f"observed require_auth* (body excerpt: {function.body[:120]!r})"
            ),
        })
    return make_findings(alerts, model, **meta)


def run_unbounded_instance_storage_growth(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='202',
        legacy_code=202,
        slug='unbounded_instance_storage_growth',
        title='Potentially Unbounded Structures in Instance Storage',
        category='economic_dos',
        portability='rust_stellar',
        confidence='low',
        remediation_hint='Avoid variable-size collections inside instance partition; shard or bound length.',
    )
    coll = re.compile(r'\b(?:Vec|Map|Bytes|String)\s*(?:<|\b)', re.IGNORECASE)
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if not facts.get('writes_instance'):
            continue
        sig = function.full_source.split('{', 1)[0]
        haystack = f'{sig}\n{function.body}'
        if not coll.search(haystack):
            continue
        alerts.append({
            'code': 202,
            'message': (
                f"Instance storage write in '{tname}.{function.name}' may carry dynamic Vec/Map/Bytes/String "
                f"payloads (sig/body excerpt): {haystack[:180]!r}"
            ),
        })
    return make_findings(alerts, model, **meta)


def run_unhandled_cross_contract_failure(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='203',
        legacy_code=203,
        slug='unhandled_cross_contract_failure',
        title='Fallible External Call Without Controlled Error Boundary',
        category='cross_contract',
        portability='rust_stellar',
        confidence='medium',
        remediation_hint='Use try_invoke_contract and handle errors instead of trapping invoke_contract alone.',
    )
    plain = re.compile(r'(?<!try_)invoke_contract\s*\(')
    for tname, function, fk_key in _entries(model):
        body = function.body.replace(' ', '')
        if not plain.search(body):
            continue
        if 'try_invoke_contract' in body:
            continue
        alerts.append({
            'code': 203,
            'message': (
                f"'{tname}.{function.name}' calls invoke_contract without try_invoke_contract pairing "
                f"in heuristic scan ({function.name} body)."
            ),
        })
    return make_findings(alerts, model, **meta)


def run_dangerous_raw_val_conversion(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='204',
        legacy_code=204,
        slug='dangerous_raw_val_conversion',
        title='Complex Collection Inputs Without Explicit Checks',
        category='input_validation',
        portability='rust_stellar',
        confidence='low',
        remediation_hint='Wrap batch parameters in #[contracttype] structs and validate length/nesting.',
    )
    for tname, function, fk_key in _entries(model):
        if not function.is_entrypoint:
            continue
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if not facts.get('params_have_vec_map'):
            continue
        prefix = function.full_source.split('{', 1)[0]
        body = function.body
        if re.search(r'\.len\s*\(\s*\)\s*<=', body):
            continue
        alerts.append({
            'code': 204,
            'message': (
                f"'{tname}.{function.name}' exposes Vec/Map parameters without obvious length guard "
                f"(signature prefix: {prefix[:120]!r})."
            ),
        })
    return make_findings(alerts, model, **meta)


def run_missing_ttl_extension(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='205',
        legacy_code=205,
        slug='missing_ttl_extension',
        title='Ledger Writes Missing TTL Extension Nearby',
        category='storage_ttl',
        portability='rust_stellar',
        confidence='low',
        remediation_hint='Call extend_ttl after persistent/instance writes or document keepers.',
    )
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if facts.get('writes_temporary'):
            continue
        if not (facts.get('writes_instance') or facts.get('writes_persistent')):
            continue
        if facts.get('calls_extend_ttl'):
            continue
        alerts.append({
            'code': 205,
            'message': (
                f"'{tname}.{function.name}' writes instance/persistent storage without observed extend_ttl "
                f"in the same function (heuristic false positives possible)."
            ),
        })
    return make_findings(alerts, model, **meta)


def run_improper_error_signaling(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='206',
        legacy_code=206,
        slug='improper_error_signaling',
        title='Bare panic! / assert! Instead of Structured Contract Errors',
        category='fuzzing_quality',
        portability='rust_stellar',
        confidence='high',
        remediation_hint='Prefer panic_with_error! with ContractError for fuzzer-visible abort classes.',
    )
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if facts.get('panic_bare') or facts.get('panic_assert'):
            alerts.append({
                'code': 206,
                'message': (
                    f"'{tname}.{function.name}' uses panic! or assert! (prefer panic_with_error! for diagnostics)."
                ),
            })
    return make_findings(alerts, model, **meta)


def run_resource_limit_exhaustion_loop(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='207',
        legacy_code=207,
        slug='resource_limit_exhaustion_loop',
        title='Loops Over Storage That May Exhaust IO Budget',
        category='economic_dos',
        portability='rust_stellar',
        confidence='medium',
        remediation_hint='Avoid storage reads inside unbounded loops; prefetch pages with caps.',
    )
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if not facts.get('reads_storage_in_loop'):
            continue
        alerts.append({
            'code': 207,
            'message': (
                f"'{tname}.{function.name}' loops while touching env.storage accessors "
                f"(risk of ledger read amplification)."
            ),
        })
    return make_findings(alerts, model, **meta)


def run_constructor_reinitialization_risk(context):
    model = context.normalized_model
    alerts = []
    meta = dict(
        task_id='208',
        legacy_code=208,
        slug='constructor_reinitialization_risk',
        title='Constructor-Like Entry Missing Reinitialization Guards',
        category='upgrade_migration',
        portability='rust_stellar',
        confidence='low',
        remediation_hint='Ensure __constructor cannot rewrite admin keys after initialization.',
    )
    for tname, function, fk_key in _entries(model):
        facts = (model.findings_data.function_facts or {}).get(fk_key) or {}
        if not facts.get('__constructor_like'):
            continue
        body = function.body.lower()
        if facts.get('mutates_ledger_like') and 'has(' not in body and 'get(' not in body:
            alerts.append({
                'code': 208,
                'message': (
                    f"'{tname}.{function.name}' performs storage mutation without observable has()/get() guard "
                    f"(migration safety review)."
                ),
            })
    return make_findings(alerts, model, **meta)

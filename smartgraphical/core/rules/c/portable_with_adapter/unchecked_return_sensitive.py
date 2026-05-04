"""Rule C03 (task 103): unchecked_return_sensitive.

Detects calls to security-critical APIs (cryptographic hashes, workspace
allocators, QUIC connection operations) whose return value is neither
assigned nor checked in a branch or assertion. Silent failures in these
APIs can lead to inconsistent state or memory corruption.

Scope: portable_with_adapter  (logic is portable; the API dictionary is
       domain-specific and should be extended per target)
Priority: 24
"""
import re

from smartgraphical.core.engine import make_findings

# APIs whose return values must always be inspected.
# Extend this list as the target code base grows.
_SECURITY_CRITICAL_PREFIXES = [
    'fd_sha256',
    'fd_sha512',
    'fd_sha3',
    'fd_hmac',
    'fd_ed25519_verify',
    'fd_ecdsa_verify',
    'fd_workspace_alloc',
    'fd_quic_',
    'fd_rng_',
    'verify',
    'authenticate',
    'decrypt',
    'encrypt',
]

# A standalone call looks like: identifier( ... )
# with no leading assignment operator.
_STANDALONE_CALL = re.compile(r'^(\w+)\s*\(')
_HAS_ASSIGNMENT = re.compile(r'=\s*\w+\s*\(')

# Prefixes that indicate the call is already guarded.
_GUARDED_PREFIXES = ('if', 'return', 'FD_TEST', 'FD_LIKELY', 'FD_UNLIKELY', 'assert')

_META = dict(
    task_id='103',
    legacy_code=103,
    slug='unchecked_return_sensitive',
    title='Unchecked Return Value in Security Critical Calls',
    category='improper_error_handling',
    portability='portable_with_adapter',
    confidence='high',
    remediation_hint=(
        'Check return codes from security-critical APIs using FD_TEST, '
        'FD_UNLIKELY, or conditional checks before proceeding.'
    ),
)


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if not any(api in stmt for api in _SECURITY_CRITICAL_PREFIXES):
                    continue
                # Already assigned or used as a condition.
                if _HAS_ASSIGNMENT.search(stmt):
                    continue
                # Already wrapped in a guard macro or conditional.
                if any(stmt.startswith(prefix) for prefix in _GUARDED_PREFIXES):
                    continue
                # Must look like a standalone call at the start of the statement.
                m = _STANDALONE_CALL.match(stmt)
                if not m:
                    continue
                called = m.group(1)
                if any(api in called for api in _SECURITY_CRITICAL_PREFIXES):
                    alerts.append({
                        'code': 103,
                        'message': (
                            f"Unchecked return from security-critical call "
                            f"'{called}' in "
                            f"{type_entry.name}.{function.name}: {stmt[:120]}"
                        ),
                    })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

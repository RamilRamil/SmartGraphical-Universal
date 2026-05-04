"""Rule C05 (task 105): incomplete_reserved_account_list.

Checks whether a Firedancer source file that defines the fd_pack unwritable
account registry is missing any of the canonical Solana sysvar / reserved
program addresses that Agave always treats as unwritable.

A missing entry causes the leader to accept writes to a reserved account,
producing a block whose hash diverges from Agave's, triggering a fork.

PoC approach:
- Search context.unified_code for the registry definition marker.
- Extract quoted base58-style pubkey strings from the surrounding code.
- Compare against a hardcoded list of required addresses.
- Fire once per missing address (confidence: medium; human must verify
  against the exact Agave release and active feature gates).

Scope: node_specific
Priority: 32
External reference: agave/sdk/reserved-account-keys/src/lib.rs
  -- pin to exact commit or release tag before each audit.
"""
import re

from smartgraphical.core.engine import make_findings

# Canonical Solana sysvar / reserved program addresses that must appear in
# any correct implementation of the unwritable account list.
# Source: Agave SDK reserved_account_keys (mainnet-beta baseline).
# Update this set when new feature gates activate new reserved addresses.
_REQUIRED_PUBKEYS = frozenset({
    'SysvarC1ock11111111111111111111111111111111',
    'SysvarRecentB1ockHashes11111111111111111111',
    'SysvarRent111111111111111111111111111111111',
    'SysvarStakeHistory1111111111111111111111111',
    'SysvarEpochSchedu1e111111111111111111111111',
    'SysvarFees111111111111111111111111111111111',
    'Sysvar1nstructions1111111111111111111111111',
    'SysvarS1otHashes111111111111111111111111111',
    'SysvarS1otHistory11111111111111111111111111',
    '11111111111111111111111111111111',
    'Vote111111111111111111111111111111111111111',
})

# Marker that identifies this file as containing the unwritable registry.
_REGISTRY_MARKER = re.compile(
    r'fd_pack_unwritable|unwritable_accts|unwritable_accounts|'
    r'FD_PACK_UNWRITABLE',
    re.IGNORECASE,
)

# Extract all quoted strings that look like base58 pubkeys (32-44 chars,
# alphanumeric without 0/O/I/l ambiguities expected but not enforced here).
_QUOTED_KEY = re.compile(r'"([A-HJ-NP-Za-km-z1-9]{32,44})"')

_META = dict(
    task_id='105',
    legacy_code=105,
    slug='incomplete_reserved_account_list',
    title='Missing Reserved Account in Unwritable List',
    category='consensus_failure',
    portability='node_specific',
    confidence='medium',
    remediation_hint=(
        'Synchronize the local unwritable account list with the pinned '
        'Agave reserved_account_keys registry (exact commit or release tag). '
        'Verify active feature gates for the target cluster before adding.'
    ),
)


def _detect(context):
    source = context.unified_code
    if not source or not _REGISTRY_MARKER.search(source):
        # Precondition not met: this file does not define the registry.
        return []

    present = {m.group(1) for m in _QUOTED_KEY.finditer(source)}
    missing = _REQUIRED_PUBKEYS - present

    alerts = []
    for key in sorted(missing):
        alerts.append({
            'code': 105,
            'message': (
                f"Required reserved account not found in unwritable registry: "
                f"'{key}' -- verify against pinned Agave SDK release."
            ),
        })
    return alerts


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

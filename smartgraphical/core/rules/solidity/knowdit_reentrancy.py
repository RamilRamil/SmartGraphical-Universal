"""Tasks 15-17: Knowdit-style advanced reentrancy heuristics on the normalized model.

Heuristics approximate audit specs: inconsistent reads across external calls (15),
retry/idempotency ordering in bridge flows (16), and CEI-style share burns on unstake (17).
"""
import re

from smartgraphical.core.engine import make_findings


def _stmt_reserve_write(stmt: str) -> bool:
    s = (stmt or "").lower()
    if "reserve" not in s:
        return False
    if re.search(r"\breserve\d*\s*[-+]?=", stmt):
        return True
    return "reserve" in s and ("-=" in stmt or "+=" in stmt)


def _stmt_external_effect(stmt: str) -> bool:
    if not stmt:
        return False
    tokens = (".transfer(", " transfer(", ".send(", ".call{", ".call(", "safeTransfer")
    low = stmt.lower()
    return any(t in stmt for t in tokens) or "call{" in low


def _stmt_sync_finalize(stmt: str) -> bool:
    s = re.sub(r"\s+", "", (stmt or "").lower())
    return any(
        mark in s
        for mark in ("sync(", "_sync(", "updatereserves(", "updatevirtualprice(")
    )


def _detect_read_only_oracle_gap(model):
    alerts = []
    for type_entry in model.types:
        for function in type_entry.functions:
            if not function.is_entrypoint:
                continue
            stmts = function.exploration_statements
            if not stmts:
                continue
            rw = [i for i, st in enumerate(stmts) if _stmt_reserve_write(st)]
            if not rw:
                continue
            ext_indices = [i for i, st in enumerate(stmts) if _stmt_external_effect(st)]
            sync_indices = [i for i, st in enumerate(stmts) if _stmt_sync_finalize(st)]
            for e in ext_indices:
                if not any(r < e for r in rw):
                    continue
                if not any(s > e for s in sync_indices):
                    continue
                alerts.append({
                    "code": 13,
                    "message": (
                        f"Possible read-only reentrancy window: reserve accounting updated, "
                        f"then external effect, before sync/state finalize in "
                        f"{type_entry.name}.{function.name}, stmt: {stmts[e]!r}"
                    ),
                })
                break
    return alerts


def _bridge_retry_context(function) -> bool:
    blob = (function.name + " " + " ".join(function.exploration_statements)).lower()
    if "retry" not in blob and "replay" not in blob:
        return False
    return any(
        k in blob
        for k in ("bridge", "crosschain", "cross-chain", "message", "layerzero", "wormhole")
    )


def _stmt_marks_attempt_consumed(stmt: str) -> bool:
    s = (stmt or "").lower()
    if "delete " in s and "[" in s:
        return True
    if "=" not in stmt:
        return False
    return any(
        k in s
        for k in (
            "processed",
            "completed",
            "executed",
            "claimed",
            "filled",
            "consumed",
            "finalized",
        )
    )


def _detect_bridge_retry_reentrancy(model):
    alerts = []
    for type_entry in model.types:
        for function in type_entry.functions:
            if not function.is_entrypoint:
                continue
            if not _bridge_retry_context(function):
                continue
            stmts = function.exploration_statements
            if not stmts:
                continue
            ext_idx = next((i for i, st in enumerate(stmts) if _stmt_external_effect(st)), None)
            cons_idx = next((i for i, st in enumerate(stmts) if _stmt_marks_attempt_consumed(st)), None)
            if ext_idx is None or cons_idx is None:
                continue
            if ext_idx < cons_idx:
                alerts.append({
                    "code": 14,
                    "message": (
                        f"Possible bridge retry reentrancy: external effect before idempotency/"
                        f" consumed-state update in {type_entry.name}.{function.name}, "
                        f"stmt: {stmts[ext_idx]!r}"
                    ),
                })
    return alerts


def _unstake_context(function) -> bool:
    n = function.name.lower()
    blob = " ".join(function.exploration_statements).lower()
    if "unstake" in n or "unstake" in blob:
        return True
    if "withdraw" in n and ("stake" in blob or "share" in blob):
        return True
    return False


def _stmt_user_payout(stmt: str) -> bool:
    s = (stmt or "").lower()
    if "safe" in s and "transfer" in s:
        return True
    if ".transfer(" in s or " transfer(" in s:
        return True
    if "call{" in s or ".call(" in s:
        return True
    return False


def _stmt_share_burn_or_reduce(stmt: str) -> bool:
    s = (stmt or "").lower()
    if "_burn(" in s or ".burn(" in s:
        return True
    if "burn(" in s and "burnfrom" not in s:
        return True
    if "-=" not in stmt:
        return False
    return any(k in s for k in ("share", "stake", "balance", "_balances", "staking"))


def _detect_unstake_share_order(model):
    alerts = []
    for type_entry in model.types:
        for function in type_entry.functions:
            if not function.is_entrypoint:
                continue
            if not _unstake_context(function):
                continue
            stmts = function.exploration_statements
            if not stmts:
                continue
            pay_idx = next((i for i, st in enumerate(stmts) if _stmt_user_payout(st)), None)
            burn_idx = next((i for i, st in enumerate(stmts) if _stmt_share_burn_or_reduce(st)), None)
            if pay_idx is None or burn_idx is None:
                continue
            if pay_idx < burn_idx:
                alerts.append({
                    "code": 15,
                    "message": (
                        f"Possible inconsistent unstake accounting: user payout before share burn/"
                        f" reduction in {type_entry.name}.{function.name}, stmt: {stmts[pay_idx]!r}"
                    ),
                })
    return alerts


_META_RO = dict(
    task_id="13",
    legacy_code=13,
    slug="read_only_oracle_reentrancy",
    title="Read-Only Reentrancy Window (Reserve Valuation)",
    category="AdvancedReentrancy",
    portability="portable_with_adapter",
    confidence="medium",
    remediation_hint=(
        "Finalize reserves, virtual price, or sync state before any external call that can "
        "reenter; keep view getters consistent with committed accounting."
    ),
)

_META_BR = dict(
    task_id="14",
    legacy_code=14,
    slug="bridge_retry_reentrancy",
    title="Bridge Retry Idempotency Ordering",
    category="AdvancedReentrancy",
    portability="portable_with_adapter",
    confidence="medium",
    remediation_hint=(
        "Mark bridge/relay attempts as consumed (or delete pending state) before token transfer "
        "or other externally visible effects."
    ),
)

_META_US = dict(
    task_id="15",
    legacy_code=15,
    slug="unstake_share_burn_order",
    title="Unstake Share Burn Ordering",
    category="AdvancedReentrancy",
    portability="portable_with_adapter",
    confidence="medium",
    remediation_hint=(
        "Burn or reduce staking shares before transferring rewards or principal to the user "
        "to prevent reusing the same share balance during reentrancy."
    ),
)


def run_read_only_oracle_gap(context):
    alerts = _detect_read_only_oracle_gap(context.normalized_model)
    return make_findings(alerts, context.normalized_model, **_META_RO)


def run_bridge_retry_gap(context):
    alerts = _detect_bridge_retry_reentrancy(context.normalized_model)
    return make_findings(alerts, context.normalized_model, **_META_BR)


def run_unstake_share_order(context):
    alerts = _detect_unstake_share_order(context.normalized_model)
    return make_findings(alerts, context.normalized_model, **_META_US)

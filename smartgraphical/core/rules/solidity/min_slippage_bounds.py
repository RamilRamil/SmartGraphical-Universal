"""Task 14: zero-literal min/slippage/deadline args on liquidity and swap-style calls.

Uses NormalizedCallEdge.args_map (function_to_function edges only). No full dataflow:
flags literals 0/false on parameters whose names suggest user-controlled bounds.
"""
import re

from smartgraphical.core.engine import make_findings

_LEGACY = 12

# Callee names (substring match, lowercased) for DEX / pool style operations.
_RISK_CALLEE_MARKERS = frozenset(
    (
        "addliquidity",
        "removeliquidity",
        "increaseliquidity",
        "decreaseliquidity",
        "swap",
        "exactinput",
        "exactoutput",
    )
)

# Formal parameter name hints for min-out / max-in / deadline-style bounds.
_BOUND_PARAM_SUBSTRINGS = (
    "amountoutmin",
    "amountinmax",
    "minimumamountout",
    "minamount",
    "minamounts",
    "minshares",
    "minliquidity",
    "minsqrt",
    "sqrtpricelimit",
    "sqrtpricelimitx96",
    "deadline",
    "limitthreshold",
)


def _risk_callee(target_name: str) -> bool:
    n = (target_name or "").lower()
    return any(m in n for m in _RISK_CALLEE_MARKERS)


def _param_suggests_user_bound(param: str) -> bool:
    p = (param or "").lower()
    if not p:
        return False
    return any(s in p for s in _BOUND_PARAM_SUBSTRINGS)


def _literal_is_zero_bounds_value(value: str) -> bool:
    """Treat common Solidity zero literals as missing slippage/deadline protection."""
    v = (value or "").strip().lower().replace(" ", "")
    if not v:
        return False
    if v == "0" or v == "false":
        return True
    if re.fullmatch(r"uint\d*\(0\)", v) or re.fullmatch(r"uint\(0\)", v):
        return True
    if v.startswith("uint") and v.endswith("(0)"):
        return True
    return False


def _last_arg_minish_for_add_liquidity(
    callee_lower: str, args_map: list, entry: dict,
) -> bool:
    """When parameter names are missing, many routers use arg0..argN-1; last arg is often min LP/shares."""
    if "addliquidity" not in callee_lower:
        return False
    if not args_map or len(args_map) < 2:
        return False
    if entry is not args_map[-1]:
        return False
    p = str(entry.get("param", "") or "")
    if not re.fullmatch(r"arg\d+", p):
        return False
    n = len(args_map)
    try:
        idx = int(p.replace("arg", ""))
    except ValueError:
        return False
    return idx == n - 1


def _detect(context):
    alerts = []
    model = context.normalized_model
    seen = set()
    for edge in getattr(model, "call_edges", []) or []:
        if getattr(edge, "edge_kind", "") != "function_to_function":
            continue
        tgt_name = getattr(edge, "target_name", "") or ""
        if not _risk_callee(tgt_name):
            continue
        args_map = getattr(edge, "args_map", []) or []
        if not args_map:
            continue
        callee_lower = tgt_name.lower()
        for entry in args_map:
            pname = str(entry.get("param", "") or "")
            val = str(entry.get("value", "") or "")
            sk = entry.get("source_kind", "")
            if sk != "literal":
                continue
            if not _literal_is_zero_bounds_value(val):
                continue
            if not (
                _param_suggests_user_bound(pname)
                or _last_arg_minish_for_add_liquidity(callee_lower, args_map, entry)
            ):
                continue
            key = (getattr(edge, "source_type", ""), getattr(edge, "source_name", ""), val, tgt_name, pname)
            if key in seen:
                continue
            seen.add(key)
            caller = f"{edge.source_type}.{edge.source_name}"
            stmt = getattr(edge, "callsite", "") or ""
            line_hint = ""
            line_numbers = getattr(edge, "line_numbers", []) or []
            if line_numbers:
                line_hint = f" line:{line_numbers[0]}"
            elif stmt:
                line_hint = f" line:{stmt}"
            alerts.append(
                {
                    "code": _LEGACY,
                    "message": (
                        f"Alert: zero min/slippage-style bound in call to {tgt_name} "
                        f"from {caller} ({pname}={val}){line_hint}"
                    ),
                }
            )
    return alerts


_META = dict(
    task_id="12",
    legacy_code=_LEGACY,
    slug="min_slippage_bounds",
    title="Minimum Bounds On Swap And Liquidity Calls",
    category="ComputationAndEconomics",
    portability="portable_with_adapter",
    confidence="medium",
    remediation_hint=(
        "Replace zero literals for min-amount, min-shares, and deadline parameters with "
        "user-supplied or quote-derived bounds."
    ),
)


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

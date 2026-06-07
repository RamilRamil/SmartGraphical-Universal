"""Pragmatic, heuristic intra-procedural taint over the normalized model
(feature 015).

Tracks untrusted input (function parameters; untrusted-read sources) flowing to
sensitive sinks (state mutations; sink tokens) within a single function, using
line/statement heuristics only — NO AST, NO pointer analysis (constitution
Principle I). It surfaces hypotheses (false positives/negatives expected), not
proofs. Results are additive `NormalizedFunction.taint_paths`.

See specs/015-intraprocedural-taint/contracts/taint.md.
"""
import re

# Untrusted-read source tokens: a value derived from these is tainted.
SOURCE_TOKENS = (
    "recvfrom", "recv", "read", "packet", "deserialize",
    "decode", "parse", "calldata", "msg.data",
)
# Sensitive sink tokens.
SINK_TOKENS = ("transfer", "send", "write", "store", "memcpy")
# Guard statement prefixes / tokens.
_GUARD_TOKENS = ("require", "assert")

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_TAINTED = 256


def _split_assignment(stmt):
    """Return (lhs_name, rhs) for a plain assignment, else None. Tolerates a type
    prefix ('int x = ...') by taking the last identifier before the first '='.
    Ignores ==, <=, >=, !=."""
    for i, ch in enumerate(stmt):
        if ch != "=":
            continue
        prev = stmt[i - 1] if i > 0 else ""
        nxt = stmt[i + 1] if i + 1 < len(stmt) else ""
        if prev in "=<>!" or nxt == "=":
            continue
        name = _base_name(stmt[:i])
        return (name, stmt[i + 1:]) if name else None
    return None


def _statements(function):
    stmts = getattr(function, "exploration_statements", None) or []
    if stmts:
        return [str(s) for s in stmts]
    body = getattr(function, "body", "") or ""
    return [p.strip() for p in re.split(r"[;\n]", body) if p.strip()]


def _names(text):
    return set(_IDENT.findall(text or ""))


def _base_name(token):
    ids = _IDENT.findall(token or "")
    return ids[-1] if ids else ""


def _has_source(text):
    low = (text or "").lower()
    return any(tok in low for tok in SOURCE_TOKENS)


def _is_guard(stmt):
    low = stmt.lower().lstrip()
    if low.startswith("if") or low.startswith("} else if") or low.startswith("else if"):
        return True
    return any(tok in low for tok in _GUARD_TOKENS)


def _sink_token(stmt, mutation_names):
    low = stmt.lower()
    for tok in SINK_TOKENS:
        if tok in low:
            return tok
    # `mutation_names` is a set; iterate in a stable (sorted) order so the chosen
    # sink is deterministic regardless of PYTHONHASHSEED (feature 015 nondeterminism
    # bug found during feature 016). Longest-first then alphabetical keeps the most
    # specific matching name (e.g. "lastReward" over its substring "reward").
    for name in sorted(mutation_names, key=lambda n: (-len(n), n)):
        if name and name in stmt:
            return name
    return None


def compute_taint(function):
    """Return a deterministic list of taint-path dicts for one function."""
    tainted = set()
    for inp in (getattr(function, "inputs", None) or []):
        name = _base_name(str(inp))
        if name:
            tainted.add(name)

    mutation_names = set()
    for mutation in (getattr(function, "mutations", None) or []):
        mutation_names |= _names(str(mutation))

    guard_fact_names = set()
    for guard in (getattr(function, "guard_facts", None) or []):
        expr = (
            getattr(guard, "expression", "")
            or getattr(guard, "source_statement", "")
            or str(guard)
        )
        guard_fact_names |= _names(expr)

    statements = _statements(function)
    source_index = {name: -1 for name in tainted}  # -1 = parameter origin
    guarded_names = set(name for name in tainted if name in guard_fact_names)
    paths = []
    seen = set()

    for idx, stmt in enumerate(statements):
        if len(tainted) > _MAX_TAINTED:
            break
        if _is_guard(stmt):
            for name in (_names(stmt) & tainted):
                guarded_names.add(name)

        assignment = _split_assignment(stmt)
        if assignment:
            lhs, rhs = assignment
            if (_names(rhs) & tainted) or _has_source(rhs):
                tainted.add(lhs)
                source_index.setdefault(lhs, idx)
            elif lhs in tainted:
                tainted.discard(lhs)
                guarded_names.discard(lhs)

        sink = _sink_token(stmt, mutation_names)
        if sink:
            for name in sorted(_names(stmt) & tainted):
                key = (name, idx)
                if key in seen:
                    continue
                seen.add(key)
                origin = source_index.get(name, -1)
                paths.append({
                    "source": name,
                    "sink": sink,
                    "source_index": origin,
                    "sink_index": idx,
                    "source_stmt": statements[origin] if origin >= 0 else f"parameter {name}",
                    "sink_stmt": stmt,
                    "guarded": name in guarded_names,
                })

    paths.sort(key=lambda p: (p["sink_index"], p["source"]))
    return paths


def apply_taint(model):
    """Populate `taint_paths` on every function in the model (additive)."""
    for type_entry in (getattr(model, "types", None) or []):
        for function in (getattr(type_entry, "functions", None) or []):
            function.taint_paths = compute_taint(function)

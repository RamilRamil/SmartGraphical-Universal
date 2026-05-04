"""Rule C01 (task 101): non_saturating_float_cast.

Flags direct C casts from floating-point expressions to unsigned integer
types without a saturating wrapper, where operand text suggests float/double
(heuristic: regex / literals; C adapter has no types).

Scope: c_specific
"""
import re
from typing import Tuple

from smartgraphical.core.engine import make_findings

# Matches a direct C cast to any common unsigned integer type.
_UNSIGNED_CAST = re.compile(
    r'\(\s*(?:ulong|uint64_t|uint32_t|uint16_t|uint8_t|unsigned\s+long'
    r'|unsigned\s+int|unsigned\s+short)\s*\)'
)

# Safe wrappers that produce Rust-compatible saturation behavior.
_SAFE_WRAPPERS = (
    'fd_rust_cast',
    'fd_saturating',
    'fd_uint_sat',
    'fd_ulong_sat',
)


def _skip_ws(stmt: str, i: int) -> int:
    while i < len(stmt) and stmt[i].isspace():
        i += 1
    return i


def _parse_operand(stmt: str, start: int) -> Tuple[str, int]:
    """Parse one primary/call/field-access expression; return (text, end_index)."""
    i = _skip_ws(stmt, start)
    if i >= len(stmt):
        return '', start
    if stmt[i] == '(':
        depth = 0
        j = i
        while j < len(stmt):
            c = stmt[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return stmt[i:j + 1], j + 1
            j += 1
        return stmt[i:], len(stmt)
    m = re.match(r'[A-Za-z_]\w*', stmt[i:])
    if not m:
        return '', start
    j = i + m.end()
    expr = stmt[i:j]
    while j < len(stmt) and stmt[j:j + 2] == '->':
        j += 2
        m2 = re.match(r'[A-Za-z_]\w*', stmt[j:])
        if not m2:
            break
        expr += '->' + m2.group(0)
        j += m2.end()
    if j < len(stmt) and stmt[j] == '(':
        depth = 0
        k = j
        while k < len(stmt):
            if stmt[k] == '(':
                depth += 1
            elif stmt[k] == ')':
                depth -= 1
                if depth == 0:
                    return stmt[i:k + 1], k + 1
            k += 1
        return stmt[i:], len(stmt)
    return expr, j


def _iter_unsigned_cast_operands(stmt: str):
    for m in _UNSIGNED_CAST.finditer(stmt):
        op, _end = _parse_operand(stmt, m.end())
        if op:
            yield op


def _operand_suggests_float(operand: str) -> bool:
    op = operand.strip()
    if not op:
        return False
    low = op.lower()
    if re.search(r'\b(double|float|long\s+double)\b', low):
        return True
    if re.search(
        r'(?<![A-Za-z0-9_])\d+[eE][+-]?\d+[fFlL]?(?![A-Za-z0-9_])',
        op,
    ):
        return True
    if re.search(
        r'(?<![A-Za-z0-9_])\d+\.\d*[fFlL]?(?![A-Za-z0-9_])',
        op,
    ):
        return True
    if re.search(
        r'(?<![A-Za-z0-9_])\d*\.\d+[fFlL]?(?![A-Za-z0-9_])',
        op,
    ):
        return True
    if re.search(r'\b\w*_double\b', op):
        return True
    if re.search(r'\b\w*_float\b', op):
        return True
    if re.fullmatch(r'[df]', op):
        return True
    return False


def _stmt_has_suspect_float_to_unsigned_cast(stmt: str) -> bool:
    if not _UNSIGNED_CAST.search(stmt):
        return False
    if any(w in stmt for w in _SAFE_WRAPPERS):
        return False
    return any(_operand_suggests_float(op) for op in _iter_unsigned_cast_operands(stmt))


def _detect(context):
    alerts = []
    model = context.normalized_model
    for type_entry in model.types:
        for function in type_entry.functions:
            for stmt in function.exploration_statements:
                if not _stmt_has_suspect_float_to_unsigned_cast(stmt):
                    continue
                qstmt = stmt[:200].replace("'", "")
                alerts.append({
                    'code': 101,
                    'message': (
                        f"Heuristic: suspected float-to-unsigned cast vs Rust parity in "
                        f"{type_entry.name}.{function.name}: '{qstmt}'"
                    ),
                })
    return alerts


_META = dict(
    task_id='101',
    legacy_code=101,
    slug='non_saturating_float_cast',
    title='C float-to-unsigned cast (Rust parity heuristic)',
    category='consensus_failure',
    portability='c_specific',
    confidence='medium',
    remediation_hint=(
        'If the operand is floating-point, use fd_rust_cast_double_to_ulong '
        'or an equivalent saturating helper for Rust-aligned semantics.'
    ),
)


def run(context):
    return make_findings(_detect(context), context.normalized_model, **_META)

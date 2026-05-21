"""Heuristic Solidity storage read/write classification for graph and rules."""
import re
from typing import Dict, List, Sequence, Tuple

from smartgraphical.core.model import NormalizedStateAccess

_COMPARISON_OPS = ("==", "!=", "<=", ">=", "=>")
_COMPOUND_ASSIGN_OPS = ("+=", "-=", "*=", "/=", "%=")
_VIEW_PURE_MODIFIERS = frozenset({"view", "pure"})
_STORAGE_BIND_RE = re.compile(
    r"\bstorage\s+(\w+)\s*=\s*[^;]*?\b(\w+)\s*\[",
    re.IGNORECASE,
)


def whole_token_pattern(name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")


def function_is_view_or_pure(modifiers: Sequence[str]) -> bool:
    lowered = {str(m).strip().lower() for m in (modifiers or [])}
    return bool(lowered & _VIEW_PURE_MODIFIERS)


def _normalize_statement(statement: str) -> str:
    text = statement.replace("\n", " ").replace("\t", " ").strip()
    while text.startswith("}"):
        text = text[1:].lstrip()
    if "//" in text:
        tail = text.split("//")[-1].strip()
        if tail and ("=" in tail or "+=" in tail or "-=" in tail):
            text = tail
        else:
            text = text.split("//", 1)[0].strip()
    return text


def split_body(body: str) -> List[str]:
    return [_normalize_statement(part) for part in body.split(";") if _normalize_statement(part)]


def _strip_comparison_operators(stmt: str) -> str:
    result = stmt
    for op in _COMPARISON_OPS:
        result = result.replace(op, " " * len(op))
    return result


def has_assigning_equals(stmt: str) -> bool:
    for op in _COMPOUND_ASSIGN_OPS:
        if op in stmt:
            return True
    stripped = _strip_comparison_operators(stmt)
    for index, char in enumerate(stripped):
        if char != "=":
            continue
        if index > 0 and stripped[index - 1] in "<>!=":
            continue
        if index + 1 < len(stripped) and stripped[index + 1] == "=":
            continue
        return True
    return False


def _first_assign_split(stmt: str) -> Tuple[str, str]:
    stripped = _strip_comparison_operators(stmt)
    for index, char in enumerate(stripped):
        if char != "=":
            continue
        if index > 0 and stripped[index - 1] in "<>!=":
            continue
        if index + 1 < len(stripped) and stripped[index + 1] == "=":
            continue
        return stmt[:index], stmt[index + 1 :]
    return stmt, ""


def token_in_part(part: str, name: str) -> bool:
    return bool(whole_token_pattern(name).search(part))


def is_local_load_from_storage(stmt: str, name: str) -> bool:
    if not has_assigning_equals(stmt) or not token_in_part(stmt, name):
        return False
    lhs, rhs = _first_assign_split(stmt)
    return token_in_part(rhs, name) and not token_in_part(lhs, name)


def collect_storage_aliases(body: str, state_names: Sequence[str]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    state_set = set(state_names)
    for stmt in split_body(body):
        for match in _STORAGE_BIND_RE.finditer(stmt):
            alias_id = match.group(1)
            root_var = match.group(2)
            if root_var in state_set and alias_id not in aliases:
                aliases[alias_id] = root_var
    return aliases


def _statement_writes_to_alias_field(stmt: str, alias: str) -> bool:
    pattern = re.compile(
        rf"\b{re.escape(alias)}\s*\.\s*\w+\s*(?:{'|'.join(re.escape(op) for op in _COMPOUND_ASSIGN_OPS)})?=",
        re.IGNORECASE,
    )
    return bool(pattern.search(stmt))


def statement_writes_to_var(
    stmt: str,
    name: str,
    aliases: Dict[str, str],
) -> bool:
    if is_local_load_from_storage(stmt, name):
        return False
    if not has_assigning_equals(stmt):
        return False
    lhs, _rhs = _first_assign_split(stmt)
    if token_in_part(lhs, name):
        return True
    for alias_id, root_var in aliases.items():
        if root_var == name and _statement_writes_to_alias_field(stmt, alias_id):
            return True
    return False


def statement_reads_var(
    stmt: str,
    name: str,
    aliases: Dict[str, str],
) -> bool:
    if not token_in_part(stmt, name):
        return False
    if statement_writes_to_var(stmt, name, aliases):
        return False
    return True


def collect_function_state_accesses(
    body: str,
    state_names: Sequence[str],
    modifiers: Sequence[str],
) -> Tuple[List[NormalizedStateAccess], List[NormalizedStateAccess], List[str]]:
    reads: List[NormalizedStateAccess] = []
    writes: List[NormalizedStateAccess] = []
    mutations: List[str] = []

    if not state_names:
        return reads, writes, mutations

    ordered_names = sorted(set(state_names), key=len, reverse=True)
    statements = split_body(body)

    if function_is_view_or_pure(modifiers):
        for stmt in statements:
            for name in ordered_names:
                if token_in_part(stmt, name):
                    entry = NormalizedStateAccess(name, "read", stmt)
                    if entry not in reads:
                        reads.append(entry)
        return reads, writes, mutations

    aliases = collect_storage_aliases(body, ordered_names)
    for stmt in statements:
        for name in ordered_names:
            if statement_writes_to_var(stmt, name, aliases):
                entry = NormalizedStateAccess(name, "write", stmt)
                if entry not in writes:
                    writes.append(entry)
                if stmt not in mutations:
                    mutations.append(stmt)
            elif statement_reads_var(stmt, name, aliases):
                entry = NormalizedStateAccess(name, "read", stmt)
                if entry not in reads:
                    reads.append(entry)

    return reads, writes, mutations

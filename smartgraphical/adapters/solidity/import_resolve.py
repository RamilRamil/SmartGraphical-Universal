"""Resolve relative Solidity import paths and load transitive local sources."""
import os
import re
from typing import List, Set

_SOL_IMPORT_PATH_RE = re.compile(
    r"""(?:from\s+["']([^"']+\.sol)["'])|(?:import\s+["']([^"']+\.sol)["'])""",
    re.IGNORECASE,
)
_MAX_IMPORT_DEPTH = 16


def extract_local_sol_import_paths(text: str) -> List[str]:
    paths: List[str] = []
    for match in _SOL_IMPORT_PATH_RE.finditer(text):
        raw = match.group(1) or match.group(2) or ""
        raw = raw.strip()
        if not raw or raw.startswith("@"):
            continue
        if raw not in paths:
            paths.append(raw)
    return paths


def resolve_import_path(source_file: str, import_path: str) -> str | None:
    if not source_file or not import_path:
        return None
    if import_path.startswith("@"):
        return None
    base_dir = os.path.dirname(os.path.abspath(source_file))
    candidate = os.path.normpath(os.path.join(base_dir, import_path))
    if os.path.isfile(candidate):
        return candidate
    return None


def collect_lines_with_imports(
    source_path: str,
    read_file,
    *,
    seen: Set[str] | None = None,
    depth: int = 0,
) -> List[str]:
    """Depth-first load of primary file and resolvable relative .sol imports.

    Used for single-file analysis only. Bundle uploads analyze each member
    without this merge (see ``parse_source(..., expand_local_imports=False)``).
    """
    if seen is None:
        seen = set()
    if depth > _MAX_IMPORT_DEPTH:
        return []
    abs_path = os.path.abspath(source_path)
    if abs_path in seen:
        return []
    seen.add(abs_path)

    lines = read_file(abs_path)
    merged: List[str] = list(lines)
    try:
        raw_text = "".join(lines)
    except TypeError:
        raw_text = "".join(str(line) for line in lines)

    for import_path in extract_local_sol_import_paths(raw_text):
        resolved = resolve_import_path(abs_path, import_path)
        if not resolved:
            continue
        merged.extend(
            collect_lines_with_imports(
                resolved,
                read_file,
                seen=seen,
                depth=depth + 1,
            ),
        )
    return merged

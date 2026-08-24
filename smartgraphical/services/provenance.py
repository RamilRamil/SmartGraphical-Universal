"""Run provenance: tool version and rules-catalog fingerprint.

Both values answer "which analyzer produced this JSON?" and must be stable for
a given build: consumers diff runs against each other and a drifting fingerprint
turns a clean diff into noise. Neither helper touches the network or shells out.
"""
import hashlib
import os


TOOL_NAME = "smartgraphical"

# Catalog files are discovered rather than listed so a new language's catalog is
# fingerprinted the day it lands. `*.schema.json` describes a catalog and is not
# one, so it stays out of the digest.
_CATALOG_SUFFIX = "_rules_catalog.json"


def repo_root():
    """Directory holding ``smartgraphical/`` and ``docs/`` (the installed root)."""
    package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(package_dir)


def tool_version():
    """Build identity, from SG_TOOL_VERSION; "unknown" when unset.

    Deliberately does not shell out to git: the analyzer image ships no git and
    no .git directory, and a subprocess per run would be latency for nothing.
    """
    explicit = os.environ.get("SG_TOOL_VERSION")
    if explicit and explicit.strip():
        return explicit.strip()
    return "unknown"


def rules_catalog_paths(root=None):
    """Every rules-catalog JSON under docs/, in stable relative-path order."""
    base = os.path.join(root or repo_root(), "docs")
    if not os.path.isdir(base):
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(_CATALOG_SUFFIX):
                found.append(os.path.join(dirpath, name))
    return sorted(found, key=lambda path: os.path.relpath(path, base).replace(os.sep, "/"))


def rules_catalog_hash(root=None):
    """SHA-256 over the catalog set; "" when no catalog ships with this build."""
    paths = rules_catalog_paths(root)
    if not paths:
        return ""
    base = os.path.join(root or repo_root(), "docs")
    digest = hashlib.sha256()
    for path in paths:
        # The relative name is hashed too, so moving a catalog is a visible change.
        digest.update(os.path.relpath(path, base).replace(os.sep, "/").encode("utf-8"))
        digest.update(b"\0")
        with open(path, "rb") as handle:
            digest.update(handle.read())
        digest.update(b"\0")
    return digest.hexdigest()

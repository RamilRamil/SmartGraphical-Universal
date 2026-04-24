"""Local HTTP server entry point.

Contract:
- Host defaults to 127.0.0.1 (no external exposure) and can be overridden
  with SG_HTTP_HOST (set to 0.0.0.0 only when running inside a container
  whose port is mapped to the host).
- Port is configurable via SG_HTTP_PORT, default 8765.
- Workspace is configurable via SG_WORKSPACE, default ./workspace.
- Database path is configurable via SG_DATABASE, default <workspace>/history.db.
- Static frontend dir: <repo>/frontend/dist (mounted only if it exists).
"""
import os
import sys

import uvicorn

from smartgraphical.interfaces.http.app import create_app
from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import HistoryService


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_WORKSPACE_DIR = "workspace"
DEFAULT_FRONTEND_DIR = os.path.join("frontend", "dist")


def _resolve_workspace():
    path = os.environ.get("SG_WORKSPACE") or DEFAULT_WORKSPACE_DIR
    return os.path.abspath(path)


def _resolve_database(workspace_path):
    path = os.environ.get("SG_DATABASE")
    if path:
        return os.path.abspath(path)
    return os.path.join(workspace_path, "history.db")


def _resolve_port():
    raw = os.environ.get("SG_HTTP_PORT")
    if not raw:
        return DEFAULT_PORT
    try:
        port = int(raw)
    except ValueError:
        return DEFAULT_PORT
    if port <= 0 or port > 65535:
        return DEFAULT_PORT
    return port


def _resolve_host():
    raw = os.environ.get("SG_HTTP_HOST")
    if not raw:
        return DEFAULT_HOST
    return raw.strip() or DEFAULT_HOST


def _resolve_frontend_dir():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(repo_root, DEFAULT_FRONTEND_DIR)
    if os.path.isdir(candidate):
        return candidate
    return None


def build_app():
    workspace_path = _resolve_workspace()
    database_path = _resolve_database(workspace_path)

    store = SqliteStore(database_path)
    artifacts = ArtifactRepository(store)
    scans = ScanRepository(store)
    service = HistoryService(
        store=store,
        artifact_repository=artifacts,
        scan_repository=scans,
        workspace_path=workspace_path,
        repo_root=os.path.dirname(os.path.abspath(__file__)),
    )
    return create_app(service, static_dir=_resolve_frontend_dir())


def main():
    host = _resolve_host()
    port = _resolve_port()
    uvicorn.run(build_app(), host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())

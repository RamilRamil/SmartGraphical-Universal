"""HTTP routes that expose web_api and HistoryService.

Conventions:
- All routes live under /api.
- Handlers call services; they never touch repositories or adapters directly.
- Responses are plain dicts; schemas.py documents them for OpenAPI.
"""
import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from smartgraphical.upload_limits import (
    MAX_MULTIPART_SOURCE_FILES,
    MAX_UPLOAD_BYTES_PER_FILE,
)
from smartgraphical.services import web_api
from smartgraphical.services.history_service import (
    ERROR_INVALID_PAYLOAD,
    ERROR_UNSUPPORTED_FILE,
    HistoryError,
    HistoryService,
)

from .schemas import RunScanRequest


def get_history_service(request: Request) -> HistoryService:
    service = getattr(request.app.state, "history_service", None)
    if service is None:
        raise HTTPException(status_code=500, detail="history service is not configured")
    return service


def build_router() -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/health")
    def health():
        return web_api.health()

    @router.get("/languages/{language}/tasks")
    def list_tasks(language: str):
        return web_api.list_tasks(language)

    @router.post("/artifacts", status_code=201)
    async def upload_artifact(
        file: UploadFile = File(...),
        service: HistoryService = Depends(get_history_service),
    ):
        data = await file.read()
        if len(data) == 0:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
        if len(data) > MAX_UPLOAD_BYTES_PER_FILE:
            raise HistoryError(
                ERROR_UNSUPPORTED_FILE,
                f"upload exceeds {MAX_UPLOAD_BYTES_PER_FILE} bytes",
            )
        return service.ingest_upload(data, file.filename or "source")

    @router.post("/artifacts/batch", status_code=200)
    async def upload_artifacts_batch(
        files: list[UploadFile] = File(...),
        service: HistoryService = Depends(get_history_service),
    ):
        """Ingest multiple files as separate artifacts (mode 1: independent uploads).

        Each file is validated like POST /artifacts. Per-file failures appear in
        ``items`` with ``ok: false``; the response is still 200 if the request
        shape is valid. Empty batch or too many files -> 400.
        """
        if not files:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "no files in batch")
        if len(files) > MAX_MULTIPART_SOURCE_FILES:
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                f"batch exceeds {MAX_MULTIPART_SOURCE_FILES} files",
            )
        items = []
        ok_count = 0
        for upload in files:
            name = upload.filename or "source"
            try:
                data = await upload.read()
                if len(data) == 0:
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
                if len(data) > MAX_UPLOAD_BYTES_PER_FILE:
                    raise HistoryError(
                        ERROR_UNSUPPORTED_FILE,
                        f"upload exceeds {MAX_UPLOAD_BYTES_PER_FILE} bytes",
                    )
                artifact = service.ingest_upload(data, name)
                items.append({"ok": True, "artifact": artifact})
                ok_count += 1
            except HistoryError as exc:
                items.append({
                    "ok": False,
                    "filename": name,
                    "code": exc.code,
                    "message": exc.message,
                })
        return {
            "items": items,
            "summary": {
                "ok": ok_count,
                "error": len(items) - ok_count,
            },
        }

    @router.post("/artifacts/bundle", status_code=201)
    async def upload_artifact_bundle(
        files: list[UploadFile] = File(
            ...,
            description=(
                "Multipart parts named 'files' (repeat per file). Creates one artifact; "
                "all parts must be the same language: .sol only, .rs only, or .c/.h mix. "
                f"Limits: empty batch rejected; at most {MAX_MULTIPART_SOURCE_FILES} files; each part at most 2 MiB; "
                "total bundle at most 64 MiB (enforced on ingest)."
            ),
        ),
        bundle_paths_json: str | None = Form(
            None,
            description=(
                "Optional JSON array of strings, one per file, same order as 'files'. "
                "When set, each entry is a POSIX relative path for that upload (tree layout, "
                "manifest version 2 with layout 'tree'). When omitted, paths default to upload "
                "basenames with collision suffixes (flat layout, manifest version 1). "
                "Paths must be relative (no leading '/', no '..', no Windows drive roots), "
                "unique after normalization, within server length/segment limits. "
                "HTTP 400 with code 'invalid_payload': invalid JSON, not an array, length "
                "mismatch, non-string entries, duplicate paths, path rules, empty file, "
                "mixed languages, or too many files. Code 'unsupported_file': per-file or "
                "total size over limit or disallowed extension."
            ),
        ),
        service: HistoryService = Depends(get_history_service),
    ):
        """Ingest multiple files as one artifact (combined graph / single scan target).

        Error contract (JSON body ``{status, code, message}``) uses ``invalid_payload`` or
        ``unsupported_file`` for validation failures, same as other HistoryService ingest routes.
        """
        if not files:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "no files in bundle")
        if len(files) > MAX_MULTIPART_SOURCE_FILES:
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                f"batch exceeds {MAX_MULTIPART_SOURCE_FILES} files",
            )
        tree_mode = False
        path_hints: list[str] = []
        if bundle_paths_json is not None and str(bundle_paths_json).strip():
            try:
                parsed = json.loads(bundle_paths_json)
            except json.JSONDecodeError as exc:
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "bundle_paths_json must be valid JSON",
                ) from exc
            if not isinstance(parsed, list):
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "bundle_paths_json must be a JSON array",
                )
            if len(parsed) != len(files):
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "bundle_paths_json length must match files count",
                )
            for item in parsed:
                if not isinstance(item, str):
                    raise HistoryError(
                        ERROR_INVALID_PAYLOAD,
                        "bundle_paths_json entries must be strings",
                    )
            tree_mode = True
            path_hints = list(parsed)

        parts = []
        for idx, upload in enumerate(files):
            data = await upload.read()
            if len(data) == 0:
                raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
            if len(data) > MAX_UPLOAD_BYTES_PER_FILE:
                raise HistoryError(
                    ERROR_UNSUPPORTED_FILE,
                    f"upload exceeds {MAX_UPLOAD_BYTES_PER_FILE} bytes",
                )
            hint = path_hints[idx] if tree_mode else (upload.filename or "source")
            parts.append((data, hint))
        return service.ingest_bundle_upload(parts, tree_mode=tree_mode)

    @router.get("/artifacts")
    def list_artifacts(
        limit: int = 50,
        service: HistoryService = Depends(get_history_service),
    ):
        return {"items": service.list_artifacts(limit=limit)}

    @router.get("/artifacts/{artifact_id}")
    def get_artifact(
        artifact_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        return service.get_artifact(artifact_id)

    @router.post("/artifacts/{artifact_id}/scans", status_code=201)
    def create_scan(
        artifact_id: int,
        payload: RunScanRequest,
        service: HistoryService = Depends(get_history_service),
    ):
        if payload.task == "all":
            return service.run_all(artifact_id, mode=payload.mode)
        return service.run_analysis(artifact_id, task_id=payload.task, mode=payload.mode)

    @router.get("/scans")
    def list_scans(
        artifact_id: int | None = None,
        limit: int = 50,
        service: HistoryService = Depends(get_history_service),
    ):
        return {"items": service.list_scans(artifact_id=artifact_id, limit=limit)}

    @router.get("/scans/{scan_id}")
    def get_scan(
        scan_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        return service.get_scan(scan_id)

    @router.get("/scans/{scan_id}/findings")
    def get_findings(
        scan_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        return {"items": service.get_findings(scan_id)}

    @router.get("/scans/{scan_id}/graph")
    def get_graph(
        scan_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        payload = service.get_graph(scan_id)
        if payload is None:
            return {"available": False}
        return {"available": True, "graph": payload}

    @router.get("/scans/{scan_id}/diff/{other_id}")
    def diff_scans(
        scan_id: int,
        other_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        return service.diff_scans(scan_id, other_id)

    @router.delete("/scans/{scan_id}")
    def soft_delete_scan(
        scan_id: int,
        service: HistoryService = Depends(get_history_service),
    ):
        deleted = service.soft_delete_scan(scan_id)
        return {"deleted": bool(deleted), "scan_id": scan_id}

    return router

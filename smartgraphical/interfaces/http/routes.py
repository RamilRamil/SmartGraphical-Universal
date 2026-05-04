"""HTTP routes that expose web_api and HistoryService.

Conventions:
- All routes live under /api.
- Handlers call services; they never touch repositories or adapters directly.
- Responses are plain dicts; schemas.py documents them for OpenAPI.
"""
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from smartgraphical.services import web_api
from smartgraphical.services.history_service import (
    ERROR_INVALID_PAYLOAD,
    ERROR_UNSUPPORTED_FILE,
    HistoryError,
    HistoryService,
)

from .schemas import RunScanRequest


MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_BATCH_ARTIFACT_FILES = 32


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
        if len(data) > MAX_UPLOAD_BYTES:
            raise HistoryError(
                ERROR_UNSUPPORTED_FILE,
                f"upload exceeds {MAX_UPLOAD_BYTES} bytes",
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
        if len(files) > MAX_BATCH_ARTIFACT_FILES:
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                f"batch exceeds {MAX_BATCH_ARTIFACT_FILES} files",
            )
        items = []
        ok_count = 0
        for upload in files:
            name = upload.filename or "source"
            try:
                data = await upload.read()
                if len(data) == 0:
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
                if len(data) > MAX_UPLOAD_BYTES:
                    raise HistoryError(
                        ERROR_UNSUPPORTED_FILE,
                        f"upload exceeds {MAX_UPLOAD_BYTES} bytes",
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
        files: list[UploadFile] = File(...),
        service: HistoryService = Depends(get_history_service),
    ):
        """Ingest multiple files as one artifact (mode 2: combined graph)."""
        if not files:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "no files in bundle")
        if len(files) > MAX_BATCH_ARTIFACT_FILES:
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                f"batch exceeds {MAX_BATCH_ARTIFACT_FILES} files",
            )
        parts = []
        for upload in files:
            data = await upload.read()
            if len(data) == 0:
                raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
            if len(data) > MAX_UPLOAD_BYTES:
                raise HistoryError(
                    ERROR_UNSUPPORTED_FILE,
                    f"upload exceeds {MAX_UPLOAD_BYTES} bytes",
                )
            parts.append((data, upload.filename or "source"))
        return service.ingest_bundle_upload(parts)

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

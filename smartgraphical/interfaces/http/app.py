"""FastAPI application factory.

The factory receives an already-constructed HistoryService so the HTTP
layer does not know about SQLite, filesystem paths, or adapters. This
keeps it trivial to swap the service for a fake in tests.
"""
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .errors import register_error_handlers
from .routes import build_router


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            response = None
        if response is not None and response.status_code != 404:
            return response
        normalized = (path or "").lstrip("/")
        if normalized.startswith("api/") or normalized == "api":
            if response is not None:
                return response
            raise StarletteHTTPException(status_code=404)
        if "." in os.path.basename(normalized):
            if response is not None:
                return response
            raise StarletteHTTPException(status_code=404)
        return await super().get_response("index.html", scope)


def create_app(history_service, static_dir: str | None = None) -> FastAPI:
    app = FastAPI(
        title="SmartGraphical Local API",
        version="0.1.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.history_service = history_service
    app.include_router(build_router())
    register_error_handlers(app)
    _mount_static(app, static_dir)
    return app


def _mount_static(app: FastAPI, static_dir: str | None) -> None:
    if not static_dir:
        return
    absolute = os.path.abspath(static_dir)
    if not os.path.isdir(absolute):
        return
    app.mount(
        "/",
        SPAStaticFiles(directory=absolute, html=True, check_dir=False),
        name="frontend",
    )

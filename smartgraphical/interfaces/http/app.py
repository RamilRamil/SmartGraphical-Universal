"""FastAPI application factory.

The factory receives an already-constructed HistoryService so the HTTP
layer does not know about SQLite, filesystem paths, or adapters. This
keeps it trivial to swap the service for a fake in tests.
"""
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .errors import register_error_handlers
from .routes import build_router


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
        StaticFiles(directory=absolute, html=True, check_dir=False),
        name="frontend",
    )

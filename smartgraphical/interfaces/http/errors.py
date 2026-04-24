"""Mapping between domain errors and HTTP responses.

Design goal: the HTTP layer never leaks stack traces or raw Python exceptions.
Every error exposed to clients has a stable code and an HTTP status.
"""
from fastapi import Request
from fastapi.responses import JSONResponse

from smartgraphical.services.history_service import (
    ERROR_DIFF_MISMATCH,
    ERROR_INVALID_PAYLOAD,
    ERROR_NOT_FOUND,
    ERROR_UNSUPPORTED_FILE,
    HistoryError,
)
from smartgraphical.services.web_api import (
    ERROR_INTERNAL,
    ERROR_INVALID_LANGUAGE,
    ERROR_INVALID_MODE,
    ERROR_INVALID_PATH,
    ERROR_INVALID_TASK,
    WebApiError,
)


_CODE_TO_STATUS = {
    ERROR_INVALID_PATH: 400,
    ERROR_INVALID_LANGUAGE: 400,
    ERROR_INVALID_MODE: 400,
    ERROR_INVALID_TASK: 400,
    ERROR_INVALID_PAYLOAD: 400,
    ERROR_UNSUPPORTED_FILE: 400,
    ERROR_NOT_FOUND: 404,
    ERROR_DIFF_MISMATCH: 409,
    ERROR_INTERNAL: 500,
}


def _response_for_code(code, message):
    status = _CODE_TO_STATUS.get(code, 500)
    return JSONResponse(
        status_code=status,
        content={"status": "error", "code": code, "message": message},
    )


async def handle_history_error(request: Request, exc: HistoryError):
    return _response_for_code(exc.code, exc.message)


async def handle_web_api_error(request: Request, exc: WebApiError):
    return _response_for_code(exc.code, exc.message)


async def handle_unexpected_error(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "code": ERROR_INTERNAL,
            "message": "internal server error",
        },
    )


def register_error_handlers(app):
    app.add_exception_handler(HistoryError, handle_history_error)
    app.add_exception_handler(WebApiError, handle_web_api_error)
    app.add_exception_handler(Exception, handle_unexpected_error)

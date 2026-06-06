"""Shared web-facade primitives (feature 016, relocated from web_api).

The stable error contract plus the WebApiError-wrapping service/language
builders, used by both ``analyze_facade`` and ``task_catalog``. Depends only on
the CLI helpers; never imports ``web_api`` (avoids the documented cycle).
"""
from smartgraphical.interfaces.cli.main import _build_service, _resolve_language


ERROR_INVALID_PATH = "invalid_path"
ERROR_INVALID_LANGUAGE = "invalid_language"
ERROR_INVALID_TASK = "invalid_task"
ERROR_INVALID_MODE = "invalid_mode"
ERROR_INTERNAL = "internal_error"


class WebApiError(Exception):
    """User-facing API error with a stable code and message."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self):
        return {"status": "error", "code": self.code, "message": self.message}


def _resolve_language_safe(path, language):
    try:
        return _resolve_language(path, language)
    except Exception as exc:
        raise WebApiError(ERROR_INVALID_LANGUAGE, str(exc))


def _build_service_safe(language):
    try:
        return _build_service(language)
    except Exception as exc:
        raise WebApiError(ERROR_INVALID_LANGUAGE, str(exc))

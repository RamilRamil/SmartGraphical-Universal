"""Pydantic request/response schemas for the HTTP layer.

Schemas are intentionally permissive on response side: HistoryService and
web_api already produce stable dicts; Pydantic is used mostly for request
validation and to document the contract.
"""
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class RunScanRequest(BaseModel):
    task: str = Field(..., description="Task id (e.g. '11') or 'all'")
    mode: str = Field(default="auditor", description="auditor | legacy | explore")


class ErrorResponse(BaseModel):
    status: str = "error"
    code: str
    message: str


class HealthResponse(BaseModel):
    status: str
    service: str
    supported_languages: List[str]
    supported_modes: List[str]


class ArtifactResponse(BaseModel):
    id: int
    sha256: str
    filename: str
    language: str
    size_bytes: int
    path_on_disk: str
    created_at: str


class ArtifactListResponse(BaseModel):
    items: List[ArtifactResponse]


class ScanResponse(BaseModel):
    id: int
    artifact_id: int
    mode: str
    task: str
    rules_run_json: str
    findings_count: int
    duration_ms: int
    tool_version: str
    rules_catalog_hash: str
    findings_payload_path: str
    graph_payload_path: str
    status: str
    error_code: str
    error_message: str
    created_at: str
    deleted_at: Optional[str] = None


class ScanListResponse(BaseModel):
    items: List[ScanResponse]


class FindingsResponse(BaseModel):
    items: List[Any]


class DiffResponse(BaseModel):
    scan_a_id: int
    scan_b_id: int
    artifact_id: int
    added: List[Any]
    removed: List[Any]
    unchanged_count: int

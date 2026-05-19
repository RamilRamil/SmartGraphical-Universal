"""Orchestrates artifact ingest, scan runs, and scan diffs on top of web_api.

Contracts:
- All state-changing operations append-only (soft-delete for scans).
- Findings payloads and graph payloads live on disk as JSON, not in SQLite.
- SQLite keeps metadata and pointers only.
"""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone

from smartgraphical.upload_limits import (
    MAX_MULTIPART_SOURCE_FILES,
    MAX_UPLOAD_BYTES_PER_FILE,
)
from smartgraphical.services import web_api
from smartgraphical.services.web_api import WebApiError


ALLOWED_EXTENSIONS = (".sol", ".c", ".h", ".rs")

BUNDLE_MANIFEST_BASENAME = "sg_bundle_manifest.json"
MAX_BUNDLE_BYTES_TOTAL = 64 * 1024 * 1024
MAX_BUNDLE_REL_PATH_LEN = 512
MAX_BUNDLE_REL_PARTS = 64

ERROR_UNSUPPORTED_FILE = "unsupported_file"
ERROR_NOT_FOUND = "not_found"
ERROR_DIFF_MISMATCH = "diff_artifact_mismatch"
ERROR_INVALID_PAYLOAD = "invalid_payload"


class HistoryError(Exception):
    """User-facing history service error with a stable code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self):
        return {"status": "error", "code": self.code, "message": self.message}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _compute_sha256(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def _sanitize_filename(filename):
    if not filename:
        return "source"
    return os.path.basename(filename)


def _extract_extension(filename):
    _, extension = os.path.splitext(filename or "")
    return extension.lower()


def _normalize_bundle_rel_path(raw: str) -> str:
    if raw is None or not isinstance(raw, str):
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path must be a non-empty string")
    s = raw.strip().replace("\\", "/")
    if not s or "\x00" in s:
        raise HistoryError(ERROR_INVALID_PAYLOAD, "invalid bundle path")
    if len(s) > MAX_BUNDLE_REL_PATH_LEN:
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path is too long")
    if s.startswith("/") or (len(s) > 1 and s[1] == ":" and s[0].isalpha()):
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path must be relative")
    parts = []
    for seg in s.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                "bundle path must not contain parent segments",
            )
        parts.append(seg)
    if not parts:
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path is empty after normalization")
    if len(parts) > MAX_BUNDLE_REL_PARTS:
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path has too many segments")
    return "/".join(parts)


def _safe_write_bundle_file(bundle_root: str, rel_posix: str, data: bytes) -> str:
    """Write ``data`` to bundle_root/rel_posix; ensure path stays inside bundle_root."""
    abs_target = os.path.normpath(
        os.path.join(bundle_root, *rel_posix.split("/")),
    )
    root_real = os.path.realpath(bundle_root)
    try:
        target_real = os.path.realpath(abs_target)
    except OSError as exc:
        raise HistoryError(ERROR_INVALID_PAYLOAD, f"invalid bundle path: {exc}") from exc
    if target_real != root_real and not target_real.startswith(root_real + os.sep):
        raise HistoryError(ERROR_INVALID_PAYLOAD, "bundle path escapes bundle root")
    parent = os.path.dirname(abs_target)
    os.makedirs(parent, exist_ok=True)
    if not os.path.isfile(abs_target):
        with open(abs_target, "wb") as handle:
            handle.write(data)
    return abs_target


def _detect_tool_version(repo_root):
    explicit = os.environ.get("SG_TOOL_VERSION")
    if explicit:
        return explicit.strip()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
            if commit:
                return commit
    except Exception:
        return "unknown"
    return "unknown"


def _hash_rules_catalog(repo_root):
    candidates = [
        os.path.join(repo_root, "docs", "c_node_rules_catalog.json"),
        os.path.join(repo_root, "docs", "rust_stellar", "soroban_rules_catalog.json"),
        os.path.join(repo_root, "docs", "rust", "language_rules_catalog.json"),
    ]
    digest = hashlib.sha256()
    used_any = False
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                digest.update(handle.read())
            used_any = True
    if not used_any:
        return ""
    return digest.hexdigest()


def _finding_key(finding):
    evidences = finding.get("evidences") or []
    first = evidences[0] if evidences else {}
    return (
        finding.get("rule_id", ""),
        first.get("type_name", ""),
        first.get("function_name", ""),
        first.get("source_statement", "") or first.get("statement", ""),
        finding.get("message", ""),
    )


class HistoryService:

    def __init__(self, store, artifact_repository, scan_repository, workspace_path, repo_root=None):
        if not workspace_path:
            raise ValueError("workspace_path must be non-empty")
        self._store = store
        self._artifacts = artifact_repository
        self._scans = scan_repository
        self._workspace = os.path.abspath(workspace_path)
        self._repo_root = os.path.abspath(repo_root) if repo_root else os.path.abspath(os.getcwd())
        os.makedirs(self._workspace, exist_ok=True)
        os.makedirs(os.path.join(self._workspace, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(self._workspace, "scans"), exist_ok=True)

    def ingest_upload(self, data, filename):
        if not isinstance(data, (bytes, bytearray)):
            raise HistoryError(ERROR_INVALID_PAYLOAD, "upload payload must be bytes")
        if len(data) == 0:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "upload payload must be non-empty")
        clean_name = _sanitize_filename(filename)
        extension = _extract_extension(clean_name)
        if extension not in ALLOWED_EXTENSIONS:
            raise HistoryError(
                ERROR_UNSUPPORTED_FILE,
                f"unsupported extension {extension or '(none)'}; expected one of {ALLOWED_EXTENSIONS}",
            )
        if extension == ".sol":
            language = "solidity"
        elif extension == ".rs":
            language = "rust"
        else:
            language = "c"
        sha256 = _compute_sha256(bytes(data))

        existing = self._artifacts.get_by_sha256(sha256)
        if existing is not None:
            return existing

        artifact_dir = os.path.join(self._workspace, "artifacts", sha256)
        os.makedirs(artifact_dir, exist_ok=True)
        disk_path = os.path.join(artifact_dir, f"source{extension}")
        if not os.path.isfile(disk_path):
            with open(disk_path, "wb") as handle:
                handle.write(bytes(data))

        return self._artifacts.create(
            sha256=sha256,
            filename=clean_name,
            language=language,
            size_bytes=len(data),
            path_on_disk=disk_path,
            created_at=_now_iso(),
        )

    def ingest_bundle_upload(self, members, tree_mode=False):
        """Persist multiple sources as one artifact (one combined graph scan).

        ``members`` is a list of ``(bytes, path_hint)``. When ``tree_mode`` is
        False (legacy), ``path_hint`` is the upload filename (basename only,
        collisions get numeric suffixes). When True, ``path_hint`` is a POSIX
        relative path (may contain ``/``); normalized paths must be unique.

        Files whose extensions are not in ``ALLOWED_EXTENSIONS`` are skipped
        (folders may include README, lockfiles, etc.). Invalid paths in tree mode
        still abort the ingest.

        Manifest: ``version`` 1 (flat) or 2 (``layout: tree``).
        """
        if not members:
            raise HistoryError(ERROR_INVALID_PAYLOAD, "no files in bundle")
        if len(members) > MAX_MULTIPART_SOURCE_FILES:
            raise HistoryError(
                ERROR_INVALID_PAYLOAD,
                f"bundle exceeds {MAX_MULTIPART_SOURCE_FILES} files",
            )
        total_size = 0
        languages = []
        staged = []

        if tree_mode:
            normalized_rows = []
            for data, raw_rel in members:
                if not isinstance(data, (bytes, bytearray)):
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "upload payload must be bytes")
                if len(data) == 0:
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
                if len(data) > MAX_UPLOAD_BYTES_PER_FILE:
                    raise HistoryError(
                        ERROR_UNSUPPORTED_FILE,
                        f"upload exceeds {MAX_UPLOAD_BYTES_PER_FILE} bytes",
                    )
                rel_norm = _normalize_bundle_rel_path(raw_rel)
                extension = _extract_extension(os.path.basename(rel_norm))
                if extension not in ALLOWED_EXTENSIONS:
                    continue
                if extension == ".sol":
                    language = "solidity"
                elif extension == ".rs":
                    language = "rust"
                else:
                    language = "c"
                languages.append(language)
                total_size += len(data)
                normalized_rows.append((bytes(data), rel_norm, language))
            if not normalized_rows:
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "no bundle files remain after skipping unsupported extensions",
                )
            if len(set(languages)) != 1:
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "bundle must be single-language "
                    "(for C, .c and .h may be mixed in one bundle; "
                    "Solidity only .sol; Rust only .rs)",
                )
            language = languages[0]
            paths_only = [r[1] for r in normalized_rows]
            if len(set(paths_only)) != len(paths_only):
                raise HistoryError(ERROR_INVALID_PAYLOAD, "duplicate bundle paths after normalization")
            if total_size > MAX_BUNDLE_BYTES_TOTAL:
                raise HistoryError(
                    ERROR_UNSUPPORTED_FILE,
                    f"bundle total size exceeds {MAX_BUNDLE_BYTES_TOTAL} bytes",
                )
            for data, rel_norm, _lang in normalized_rows:
                file_hash = _compute_sha256(data)
                staged.append((rel_norm, data, file_hash))
        else:
            normalized_flat = []
            for data, filename in members:
                if not isinstance(data, (bytes, bytearray)):
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "upload payload must be bytes")
                if len(data) == 0:
                    raise HistoryError(ERROR_INVALID_PAYLOAD, "uploaded file is empty")
                if len(data) > MAX_UPLOAD_BYTES_PER_FILE:
                    raise HistoryError(
                        ERROR_UNSUPPORTED_FILE,
                        f"upload exceeds {MAX_UPLOAD_BYTES_PER_FILE} bytes",
                    )
                clean_name = _sanitize_filename(filename)
                extension = _extract_extension(clean_name)
                if extension not in ALLOWED_EXTENSIONS:
                    continue
                if extension == ".sol":
                    language = "solidity"
                elif extension == ".rs":
                    language = "rust"
                else:
                    language = "c"
                languages.append(language)
                total_size += len(data)
                normalized_flat.append((bytes(data), clean_name, language))
            if not normalized_flat:
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "no bundle files remain after skipping unsupported extensions",
                )
            if len(set(languages)) != 1:
                raise HistoryError(
                    ERROR_INVALID_PAYLOAD,
                    "bundle must be single-language "
                    "(for C, .c and .h may be mixed in one bundle; "
                    "Solidity only .sol; Rust only .rs)",
                )
            language = languages[0]
            if total_size > MAX_BUNDLE_BYTES_TOTAL:
                raise HistoryError(
                    ERROR_UNSUPPORTED_FILE,
                    f"bundle total size exceeds {MAX_BUNDLE_BYTES_TOTAL} bytes",
                )
            used_names = {}
            for data, clean_name, _lang in sorted(normalized_flat, key=lambda x: x[1]):
                base = clean_name
                candidate = base
                suffix = 0
                while candidate in used_names:
                    suffix += 1
                    stem, ext = os.path.splitext(base)
                    candidate = f"{stem}_{suffix}{ext}"
                used_names[candidate] = True
                file_hash = _compute_sha256(data)
                staged.append((candidate, data, file_hash))

        members_for_hash = [(r[0], r[2]) for r in staged]
        digest = hashlib.sha256()
        for rel_path, file_hash in sorted(members_for_hash, key=lambda x: x[0]):
            digest.update(rel_path.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(file_hash.encode("ascii"))

        bundle_sha256 = digest.hexdigest()
        existing = self._artifacts.get_by_sha256(bundle_sha256)
        if existing is not None:
            return existing

        bundle_dir = os.path.join(self._workspace, "artifacts", bundle_sha256)
        os.makedirs(bundle_dir, exist_ok=True)
        manifest_members = []
        display_names = []
        for rel_path, data, file_hash in sorted(staged, key=lambda x: x[0]):
            _safe_write_bundle_file(bundle_dir, rel_path, data)
            manifest_members.append({"path": rel_path, "sha256": file_hash})
            display_names.append(rel_path)

        if tree_mode:
            manifest = {
                "version": 2,
                "layout": "tree",
                "language": language,
                "members": manifest_members,
            }
        else:
            manifest = {
                "version": 1,
                "language": language,
                "members": manifest_members,
            }
        manifest_path = os.path.join(bundle_dir, BUNDLE_MANIFEST_BASENAME)
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=True, indent=2)

        if len(display_names) == 1:
            bundle_filename = f"bundle:{display_names[0]}"
        else:
            bundle_filename = (
                f"bundle:{display_names[0]} (+{len(display_names) - 1} more)"
            )

        return self._artifacts.create(
            sha256=bundle_sha256,
            filename=bundle_filename,
            language=language,
            size_bytes=total_size,
            path_on_disk=bundle_dir,
            created_at=_now_iso(),
        )

    def run_analysis(self, artifact_id, task_id, mode="auditor"):
        artifact = self._require_artifact(artifact_id)
        try:
            report = web_api.analyze(
                path=artifact["path_on_disk"],
                task_id=task_id,
                language=artifact["language"],
                mode=mode,
            )
        except WebApiError as exc:
            return self._persist_failed_scan(artifact, mode, str(task_id or ""), exc)
        return self._persist_successful_scan(artifact, mode, report)

    def run_all(self, artifact_id, mode="auditor"):
        artifact = self._require_artifact(artifact_id)
        graph_report = None
        try:
            report = web_api.analyze_all(
                path=artifact["path_on_disk"],
                language=artifact["language"],
                mode=mode,
            )
            graph_report = web_api.graph(
                path=artifact["path_on_disk"],
                language=artifact["language"],
            )
        except WebApiError as exc:
            return self._persist_failed_scan(artifact, mode, web_api.META_TASK_ALL_ID, exc)
        return self._persist_successful_scan(artifact, mode, report, graph_report=graph_report)

    def get_scan(self, scan_id):
        scan = self._scans.get(scan_id)
        if scan is None or scan.get("deleted_at"):
            raise HistoryError(ERROR_NOT_FOUND, f"scan {scan_id} not found")
        artifact = self._artifacts.get(scan["artifact_id"])
        findings = self._read_json(scan["findings_payload_path"], default=[])
        return {"scan": scan, "artifact": artifact, "findings": findings}

    def get_graph(self, scan_id):
        scan = self._scans.get(scan_id)
        if scan is None or scan.get("deleted_at"):
            raise HistoryError(ERROR_NOT_FOUND, f"scan {scan_id} not found")
        path = scan.get("graph_payload_path") or ""
        if not path:
            return None
        return self._read_json(path, default=None)

    def list_scans(self, artifact_id=None, limit=50):
        if artifact_id is None:
            return self._scans.list_recent(limit=limit)
        return self._scans.list_for_artifact(artifact_id, limit=limit)

    def list_artifacts(self, limit=50):
        return self._artifacts.list(limit=limit)

    def get_artifact(self, artifact_id):
        artifact = self._artifacts.get(artifact_id)
        if artifact is None:
            raise HistoryError(ERROR_NOT_FOUND, f"artifact {artifact_id} not found")
        return artifact

    def get_findings(self, scan_id):
        scan = self._scans.get(scan_id)
        if scan is None or scan.get("deleted_at"):
            raise HistoryError(ERROR_NOT_FOUND, f"scan {scan_id} not found")
        return self._read_json(scan["findings_payload_path"], default=[])

    def soft_delete_scan(self, scan_id):
        return self._scans.soft_delete(scan_id, _now_iso())

    def diff_scans(self, scan_a_id, scan_b_id):
        scan_a = self._scans.get(scan_a_id)
        scan_b = self._scans.get(scan_b_id)
        if scan_a is None or scan_b is None:
            raise HistoryError(ERROR_NOT_FOUND, "one of scans not found")
        if scan_a["artifact_id"] != scan_b["artifact_id"]:
            raise HistoryError(
                ERROR_DIFF_MISMATCH,
                "scans belong to different artifacts; diff is only allowed for the same file",
            )
        findings_a = self._read_json(scan_a["findings_payload_path"], default=[])
        findings_b = self._read_json(scan_b["findings_payload_path"], default=[])
        keyed_a = {_finding_key(item): item for item in findings_a}
        keyed_b = {_finding_key(item): item for item in findings_b}
        added = [keyed_b[key] for key in keyed_b if key not in keyed_a]
        removed = [keyed_a[key] for key in keyed_a if key not in keyed_b]
        unchanged_count = sum(1 for key in keyed_a if key in keyed_b)
        return {
            "scan_a_id": scan_a["id"],
            "scan_b_id": scan_b["id"],
            "artifact_id": scan_a["artifact_id"],
            "added": added,
            "removed": removed,
            "unchanged_count": unchanged_count,
        }

    def _require_artifact(self, artifact_id):
        artifact = self._artifacts.get(artifact_id)
        if artifact is None:
            raise HistoryError(ERROR_NOT_FOUND, f"artifact {artifact_id} not found")
        return artifact

    def _persist_successful_scan(self, artifact, mode, report, graph_report=None):
        findings_payload_path, scan_dir = self._allocate_scan_dir(artifact["id"])
        findings = report.get("findings", [])
        self._write_json(findings_payload_path, findings)
        graph_payload_path = ""
        if graph_report is not None:
            graph_payload_path = os.path.join(scan_dir, "graph.json")
            self._write_json(graph_payload_path, graph_report)

        rules_run = report.get("rules_run", [])
        task = report.get("task", "")
        return self._scans.create({
            "artifact_id": artifact["id"],
            "mode": mode,
            "task": str(task),
            "rules_run_json": json.dumps(rules_run),
            "findings_count": int(report.get("findings_count", len(findings))),
            "duration_ms": int(report.get("duration_ms", 0)),
            "tool_version": _detect_tool_version(self._repo_root),
            "rules_catalog_hash": _hash_rules_catalog(self._repo_root),
            "findings_payload_path": findings_payload_path,
            "graph_payload_path": graph_payload_path,
            "status": "ok",
            "error_code": "",
            "error_message": "",
            "created_at": _now_iso(),
        })

    def _persist_failed_scan(self, artifact, mode, task, exc):
        findings_payload_path, _ = self._allocate_scan_dir(artifact["id"])
        self._write_json(findings_payload_path, [])
        return self._scans.create({
            "artifact_id": artifact["id"],
            "mode": mode,
            "task": task,
            "rules_run_json": json.dumps([]),
            "findings_count": 0,
            "duration_ms": 0,
            "tool_version": _detect_tool_version(self._repo_root),
            "rules_catalog_hash": _hash_rules_catalog(self._repo_root),
            "findings_payload_path": findings_payload_path,
            "graph_payload_path": "",
            "status": "error",
            "error_code": getattr(exc, "code", "internal_error"),
            "error_message": str(exc),
            "created_at": _now_iso(),
        })

    def _allocate_scan_dir(self, artifact_id):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        scan_dir = os.path.join(self._workspace, "scans", f"a{artifact_id}", stamp)
        os.makedirs(scan_dir, exist_ok=True)
        return os.path.join(scan_dir, "findings.json"), scan_dir

    @staticmethod
    def _write_json(path, payload):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=False)

    @staticmethod
    def _read_json(path, default=None):
        if not path or not os.path.isfile(path):
            return default
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

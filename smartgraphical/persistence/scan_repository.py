"""Repository for analysis scan runs."""


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


class ScanRepository:

    def __init__(self, store):
        self._store = store

    def create(self, record):
        required_fields = (
            "artifact_id",
            "mode",
            "task",
            "rules_run_json",
            "findings_count",
            "duration_ms",
            "tool_version",
            "rules_catalog_hash",
            "findings_payload_path",
            "status",
            "created_at",
        )
        for field_name in required_fields:
            if field_name not in record:
                raise ValueError(f"scan record missing required field: {field_name}")

        with self._store.open() as connection:
            cursor = connection.execute(
                "INSERT INTO scan ("
                "artifact_id, mode, task, rules_run_json, findings_count, duration_ms, "
                "tool_version, rules_catalog_hash, findings_payload_path, graph_payload_path, "
                "status, error_code, error_message, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(record["artifact_id"]),
                    record["mode"],
                    record["task"],
                    record["rules_run_json"],
                    int(record["findings_count"]),
                    int(record["duration_ms"]),
                    record["tool_version"],
                    record["rules_catalog_hash"],
                    record["findings_payload_path"],
                    record.get("graph_payload_path", ""),
                    record["status"],
                    record.get("error_code", ""),
                    record.get("error_message", ""),
                    record["created_at"],
                ),
            )
            scan_id = cursor.lastrowid
        return self.get(scan_id)

    def get(self, scan_id):
        with self._store.open() as connection:
            row = connection.execute(
                "SELECT * FROM scan WHERE id = ?",
                (scan_id,),
            ).fetchone()
        return _row_to_dict(row)

    def list_for_artifact(self, artifact_id, include_deleted=False, limit=100):
        bounded_limit = max(1, min(int(limit), 500))
        query = "SELECT * FROM scan WHERE artifact_id = ?"
        params = [int(artifact_id)]
        if not include_deleted:
            query += " AND deleted_at IS NULL"
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(bounded_limit)
        with self._store.open() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_recent(self, include_deleted=False, limit=50):
        bounded_limit = max(1, min(int(limit), 500))
        query = "SELECT * FROM scan"
        if not include_deleted:
            query += " WHERE deleted_at IS NULL"
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        with self._store.open() as connection:
            rows = connection.execute(query, (bounded_limit,)).fetchall()
        return [_row_to_dict(row) for row in rows]

    def soft_delete(self, scan_id, deleted_at):
        with self._store.open() as connection:
            cursor = connection.execute(
                "UPDATE scan SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
                (deleted_at, int(scan_id)),
            )
            return cursor.rowcount > 0

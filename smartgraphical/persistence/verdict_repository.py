"""Repository for finding verdicts (feature 013: false-positive / triage).

A verdict is scoped to an artifact and keyed by a stable finding identity
(`_finding_key_hash`). One verdict per (artifact_id, finding_key); setting is an
upsert. Mirrors the ScanRepository / ArtifactRepository style.
"""
import datetime


VALID_STATUSES = ("false_positive", "accepted")


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class VerdictRepository:

    def __init__(self, store):
        self._store = store

    def upsert(self, artifact_id, finding_key, status, note=""):
        now = _utc_now()
        with self._store.open() as connection:
            connection.execute(
                "INSERT INTO finding_verdict "
                "(artifact_id, finding_key, status, note, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(artifact_id, finding_key) DO UPDATE SET "
                "status = excluded.status, note = excluded.note, "
                "updated_at = excluded.updated_at",
                (int(artifact_id), finding_key, status, note or "", now, now),
            )
        return self.get(artifact_id, finding_key)

    def get(self, artifact_id, finding_key):
        with self._store.open() as connection:
            row = connection.execute(
                "SELECT * FROM finding_verdict WHERE artifact_id = ? AND finding_key = ?",
                (int(artifact_id), finding_key),
            ).fetchone()
        return _row_to_dict(row)

    def get_by_artifact(self, artifact_id):
        with self._store.open() as connection:
            rows = connection.execute(
                "SELECT * FROM finding_verdict WHERE artifact_id = ? "
                "ORDER BY updated_at DESC, id DESC",
                (int(artifact_id),),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def delete(self, artifact_id, finding_key):
        with self._store.open() as connection:
            cursor = connection.execute(
                "DELETE FROM finding_verdict WHERE artifact_id = ? AND finding_key = ?",
                (int(artifact_id), finding_key),
            )
            return cursor.rowcount > 0

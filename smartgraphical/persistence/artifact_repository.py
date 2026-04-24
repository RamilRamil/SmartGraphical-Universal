"""Repository for uploaded artifacts."""


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


class ArtifactRepository:

    def __init__(self, store):
        self._store = store

    def create(self, sha256, filename, language, size_bytes, path_on_disk, created_at):
        with self._store.open() as connection:
            cursor = connection.execute(
                "INSERT INTO artifact "
                "(sha256, filename, language, size_bytes, path_on_disk, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (sha256, filename, language, int(size_bytes), path_on_disk, created_at),
            )
            artifact_id = cursor.lastrowid
        return self.get(artifact_id)

    def get(self, artifact_id):
        with self._store.open() as connection:
            row = connection.execute(
                "SELECT * FROM artifact WHERE id = ?",
                (artifact_id,),
            ).fetchone()
        return _row_to_dict(row)

    def get_by_sha256(self, sha256):
        if not sha256:
            return None
        with self._store.open() as connection:
            row = connection.execute(
                "SELECT * FROM artifact WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
        return _row_to_dict(row)

    def list(self, limit=50):
        bounded_limit = max(1, min(int(limit), 500))
        with self._store.open() as connection:
            rows = connection.execute(
                "SELECT * FROM artifact ORDER BY created_at DESC, id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

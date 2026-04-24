"""Unit tests for ArtifactRepository."""
import os
import sqlite3
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.sqlite_store import SqliteStore


class ArtifactRepositoryTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmpdir.name, "test.db")
        self.store = SqliteStore(db_path)
        self.repo = ArtifactRepository(self.store)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _create_sample(self, sha="abc123", filename="a.sol", language="solidity", path="/tmp/a.sol"):
        return self.repo.create(
            sha256=sha,
            filename=filename,
            language=language,
            size_bytes=42,
            path_on_disk=path,
            created_at="2030-01-01T00:00:00Z",
        )

    def test_create_and_get_returns_record(self):
        created = self._create_sample()
        self.assertIsNotNone(created)
        self.assertEqual(created["sha256"], "abc123")
        self.assertEqual(created["language"], "solidity")
        fetched = self.repo.get(created["id"])
        self.assertEqual(fetched["sha256"], "abc123")

    def test_get_returns_none_for_unknown_id(self):
        self.assertIsNone(self.repo.get(9999))

    def test_get_by_sha256_finds_record(self):
        self._create_sample(sha="deadbeef")
        found = self.repo.get_by_sha256("deadbeef")
        self.assertIsNotNone(found)
        self.assertEqual(found["sha256"], "deadbeef")

    def test_get_by_sha256_tolerates_empty(self):
        self.assertIsNone(self.repo.get_by_sha256(""))
        self.assertIsNone(self.repo.get_by_sha256(None))

    def test_duplicate_sha256_is_rejected(self):
        self._create_sample(sha="same")
        with self.assertRaises(sqlite3.IntegrityError):
            self._create_sample(sha="same", filename="b.sol", path="/tmp/b.sol")

    def test_list_orders_by_created_at_desc(self):
        self.repo.create(
            sha256="older", filename="a.sol", language="solidity",
            size_bytes=10, path_on_disk="/tmp/a.sol",
            created_at="2030-01-01T00:00:00Z",
        )
        self.repo.create(
            sha256="newer", filename="b.sol", language="solidity",
            size_bytes=10, path_on_disk="/tmp/b.sol",
            created_at="2030-06-01T00:00:00Z",
        )
        listed = self.repo.list()
        self.assertEqual(listed[0]["sha256"], "newer")
        self.assertEqual(listed[1]["sha256"], "older")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for VerdictRepository (feature 013)."""
import os
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.persistence.verdict_repository import VerdictRepository


class VerdictRepositoryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = SqliteStore(os.path.join(self._tmp.name, "history.db"))
        self.artifacts = ArtifactRepository(self.store)
        self.repo = VerdictRepository(self.store)
        artifact = self.artifacts.create(
            sha256="a" * 64,
            filename="X.sol",
            language="solidity",
            size_bytes=10,
            path_on_disk="/tmp/X.sol",
            created_at="2026-06-02T00:00:00+00:00",
        )
        self.aid = artifact["id"]

    def tearDown(self):
        self._tmp.cleanup()

    def test_upsert_inserts_then_overwrites(self):
        v1 = self.repo.upsert(self.aid, "key1", "false_positive", "noise")
        self.assertEqual(v1["status"], "false_positive")
        self.assertEqual(v1["note"], "noise")
        v2 = self.repo.upsert(self.aid, "key1", "accepted", "ack")
        self.assertEqual(v2["status"], "accepted")
        self.assertEqual(v2["note"], "ack")
        # UNIQUE(artifact_id, finding_key): still exactly one row
        self.assertEqual(len(self.repo.get_by_artifact(self.aid)), 1)

    def test_get_and_get_by_artifact(self):
        self.repo.upsert(self.aid, "k1", "false_positive")
        self.repo.upsert(self.aid, "k2", "accepted")
        self.assertEqual(self.repo.get(self.aid, "k1")["status"], "false_positive")
        self.assertIsNone(self.repo.get(self.aid, "missing"))
        self.assertEqual(len(self.repo.get_by_artifact(self.aid)), 2)

    def test_delete(self):
        self.repo.upsert(self.aid, "k1", "false_positive")
        self.assertTrue(self.repo.delete(self.aid, "k1"))
        self.assertIsNone(self.repo.get(self.aid, "k1"))
        self.assertFalse(self.repo.delete(self.aid, "k1"))

    def test_cascade_on_artifact_delete(self):
        self.repo.upsert(self.aid, "k1", "false_positive")
        with self.store.open() as conn:
            conn.execute("DELETE FROM artifact WHERE id = ?", (self.aid,))
        self.assertEqual(self.repo.get_by_artifact(self.aid), [])


if __name__ == "__main__":
    unittest.main()

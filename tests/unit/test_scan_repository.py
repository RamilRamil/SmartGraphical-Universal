"""Unit tests for ScanRepository."""
import json
import os
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore


def _make_scan_record(artifact_id, task="11", created_at="2030-01-01T00:00:00Z", findings_count=0):
    return {
        "artifact_id": artifact_id,
        "mode": "auditor",
        "task": task,
        "rules_run_json": json.dumps([task]) if task != "all" else json.dumps(["1", "2"]),
        "findings_count": findings_count,
        "duration_ms": 0,
        "tool_version": "unknown",
        "rules_catalog_hash": "",
        "findings_payload_path": "/tmp/findings.json",
        "graph_payload_path": "",
        "status": "ok",
        "error_code": "",
        "error_message": "",
        "created_at": created_at,
    }


class ScanRepositoryTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self._tmpdir.name, "test.db")
        self.store = SqliteStore(db_path)
        self.artifacts = ArtifactRepository(self.store)
        self.scans = ScanRepository(self.store)
        artifact = self.artifacts.create(
            sha256="art1", filename="a.sol", language="solidity",
            size_bytes=42, path_on_disk="/tmp/a.sol",
            created_at="2030-01-01T00:00:00Z",
        )
        self.artifact_id = artifact["id"]

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_and_get_roundtrip(self):
        created = self.scans.create(_make_scan_record(self.artifact_id))
        self.assertEqual(created["artifact_id"], self.artifact_id)
        self.assertEqual(created["status"], "ok")
        fetched = self.scans.get(created["id"])
        self.assertEqual(fetched["id"], created["id"])

    def test_create_requires_all_fields(self):
        record = _make_scan_record(self.artifact_id)
        del record["status"]
        with self.assertRaises(ValueError):
            self.scans.create(record)

    def test_list_for_artifact_excludes_deleted_by_default(self):
        a = self.scans.create(_make_scan_record(self.artifact_id, task="11", created_at="2030-01-01T00:00:00Z"))
        b = self.scans.create(_make_scan_record(self.artifact_id, task="12", created_at="2030-01-02T00:00:00Z"))
        self.scans.soft_delete(a["id"], "2030-02-01T00:00:00Z")
        listed = self.scans.list_for_artifact(self.artifact_id)
        ids = [item["id"] for item in listed]
        self.assertIn(b["id"], ids)
        self.assertNotIn(a["id"], ids)

    def test_list_for_artifact_include_deleted(self):
        a = self.scans.create(_make_scan_record(self.artifact_id))
        self.scans.soft_delete(a["id"], "2030-02-01T00:00:00Z")
        listed = self.scans.list_for_artifact(self.artifact_id, include_deleted=True)
        self.assertEqual(len(listed), 1)

    def test_list_recent_orders_by_created_at_desc(self):
        older = self.scans.create(_make_scan_record(self.artifact_id, created_at="2030-01-01T00:00:00Z"))
        newer = self.scans.create(_make_scan_record(self.artifact_id, created_at="2030-06-01T00:00:00Z"))
        listed = self.scans.list_recent()
        self.assertEqual(listed[0]["id"], newer["id"])
        self.assertEqual(listed[1]["id"], older["id"])

    def test_soft_delete_returns_false_when_already_deleted(self):
        record = self.scans.create(_make_scan_record(self.artifact_id))
        self.assertTrue(self.scans.soft_delete(record["id"], "2030-02-01T00:00:00Z"))
        self.assertFalse(self.scans.soft_delete(record["id"], "2030-02-02T00:00:00Z"))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for HistoryService."""
import os
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import (
    ERROR_DIFF_MISMATCH,
    ERROR_INVALID_PAYLOAD,
    ERROR_NOT_FOUND,
    ERROR_UNSUPPORTED_FILE,
    HistoryError,
    HistoryService,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class HistoryServiceTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._root = self._tmpdir.name
        db_path = os.path.join(self._root, "history.db")
        self.store = SqliteStore(db_path)
        self.artifacts = ArtifactRepository(self.store)
        self.scans = ScanRepository(self.store)
        self.service = HistoryService(
            store=self.store,
            artifact_repository=self.artifacts,
            scan_repository=self.scans,
            workspace_path=os.path.join(self._root, "workspace"),
            repo_root=REPO_ROOT,
        )
        with open(SIMPLE_AUCTION_PATH, "rb") as handle:
            self._source_bytes = handle.read()

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_ingest_upload_creates_artifact_and_file(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        self.assertEqual(artifact["language"], "solidity")
        self.assertEqual(artifact["filename"], "SimpleAuction.sol")
        self.assertTrue(os.path.isfile(artifact["path_on_disk"]))
        self.assertEqual(artifact["size_bytes"], len(self._source_bytes))

    def test_ingest_upload_dedups_by_sha256(self):
        first = self.service.ingest_upload(self._source_bytes, "A.sol")
        second = self.service.ingest_upload(self._source_bytes, "B.sol")
        self.assertEqual(first["id"], second["id"])

    def test_ingest_upload_rejects_unsupported_extension(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.ingest_upload(b"not code", "malware.exe")
        self.assertEqual(ctx.exception.code, ERROR_UNSUPPORTED_FILE)

    def test_ingest_upload_rejects_empty_payload(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.ingest_upload(b"", "empty.sol")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PAYLOAD)

    def test_ingest_upload_rejects_non_bytes_payload(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.ingest_upload("text-not-bytes", "a.sol")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PAYLOAD)

    def test_ingest_upload_sanitizes_filename(self):
        artifact = self.service.ingest_upload(self._source_bytes, "../../etc/pwn.sol")
        self.assertEqual(artifact["filename"], "pwn.sol")

    def test_run_analysis_creates_scan_and_findings_file(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        scan = self.service.run_analysis(artifact["id"], task_id="11", mode="auditor")
        self.assertEqual(scan["artifact_id"], artifact["id"])
        self.assertEqual(scan["task"], "11")
        self.assertEqual(scan["status"], "ok")
        self.assertTrue(os.path.isfile(scan["findings_payload_path"]))

    def test_run_analysis_records_error_for_unknown_task(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        scan = self.service.run_analysis(artifact["id"], task_id="9999")
        self.assertEqual(scan["status"], "error")
        self.assertTrue(scan["error_code"])

    def test_run_analysis_rejects_unknown_artifact(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.run_analysis(artifact_id=9999, task_id="11")
        self.assertEqual(ctx.exception.code, ERROR_NOT_FOUND)

    def test_run_all_creates_scan_and_graph_payload(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        scan = self.service.run_all(artifact["id"])
        self.assertEqual(scan["status"], "ok")
        self.assertEqual(scan["task"], "all")
        self.assertTrue(os.path.isfile(scan["graph_payload_path"]))

    def test_get_scan_returns_combined_view(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        created = self.service.run_analysis(artifact["id"], task_id="11")
        combined = self.service.get_scan(created["id"])
        self.assertEqual(combined["scan"]["id"], created["id"])
        self.assertEqual(combined["artifact"]["id"], artifact["id"])
        self.assertIsInstance(combined["findings"], list)

    def test_get_scan_rejects_deleted(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        created = self.service.run_analysis(artifact["id"], task_id="11")
        self.assertTrue(self.service.soft_delete_scan(created["id"]))
        with self.assertRaises(HistoryError) as ctx:
            self.service.get_scan(created["id"])
        self.assertEqual(ctx.exception.code, ERROR_NOT_FOUND)

    def test_list_scans_filters_by_artifact(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        self.service.run_analysis(artifact["id"], task_id="11")
        self.service.run_analysis(artifact["id"], task_id="10")
        for_artifact = self.service.list_scans(artifact["id"])
        self.assertEqual(len(for_artifact), 2)
        recent = self.service.list_scans()
        self.assertEqual(len(recent), 2)

    def test_diff_scans_returns_added_and_removed(self):
        artifact = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        scan_a = self.service.run_analysis(artifact["id"], task_id="11")
        scan_b = self.service.run_all(artifact["id"])
        diff = self.service.diff_scans(scan_a["id"], scan_b["id"])
        self.assertEqual(diff["artifact_id"], artifact["id"])
        self.assertIn("added", diff)
        self.assertIn("removed", diff)
        self.assertIn("unchanged_count", diff)
        self.assertIsInstance(diff["added"], list)
        self.assertIsInstance(diff["removed"], list)

    def test_diff_scans_rejects_different_artifacts(self):
        artifact_one = self.service.ingest_upload(self._source_bytes, "SimpleAuction.sol")
        modified = self._source_bytes + b"\n// extra comment line\n"
        artifact_two = self.service.ingest_upload(modified, "SimpleAuction2.sol")
        scan_a = self.service.run_analysis(artifact_one["id"], task_id="11")
        scan_b = self.service.run_analysis(artifact_two["id"], task_id="11")
        with self.assertRaises(HistoryError) as ctx:
            self.service.diff_scans(scan_a["id"], scan_b["id"])
        self.assertEqual(ctx.exception.code, ERROR_DIFF_MISMATCH)

    def test_diff_scans_rejects_missing_scan(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.diff_scans(1, 2)
        self.assertEqual(ctx.exception.code, ERROR_NOT_FOUND)


if __name__ == "__main__":
    unittest.main()

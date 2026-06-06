"""Integration tests for HistoryService.diff_graphs (feature 018)."""
import os
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import (
    ERROR_DIFF_MISMATCH,
    ERROR_NOT_FOUND,
    HistoryError,
    HistoryService,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")
SOL_FIXTURE_2 = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "WithdrawNoGuard.sol")


class HistoryGraphDiffTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._root = self._tmpdir.name
        store = SqliteStore(os.path.join(self._root, "history.db"))
        self.service = HistoryService(
            store=store,
            artifact_repository=ArtifactRepository(store),
            scan_repository=ScanRepository(store),
            workspace_path=os.path.join(self._root, "workspace"),
            repo_root=REPO_ROOT,
        )
        if not os.path.isfile(SOL_FIXTURE):
            self.skipTest("solidity fixture missing")
        with open(SOL_FIXTURE, "rb") as handle:
            self._bytes = handle.read()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _artifact(self, name="A.sol", data=None):
        return self.service.ingest_upload(data or self._bytes, name)

    def test_two_run_all_scans_same_artifact_diff_empty(self):
        art = self._artifact()
        a = self.service.run_all(art["id"])
        b = self.service.run_all(art["id"])
        diff = self.service.diff_graphs(a["id"], b["id"])
        self.assertTrue(diff["graph_available"])
        self.assertEqual(diff["added_nodes"], [])
        self.assertEqual(diff["removed_nodes"], [])
        self.assertEqual(diff["changed_nodes"], [])
        self.assertGreater(diff["unchanged_node_count"], 0)
        self.assertEqual(diff["artifact_id"], art["id"])
        self.assertEqual(diff["scan_a_id"], a["id"])
        self.assertEqual(diff["scan_b_id"], b["id"])

    def test_different_artifacts_rejected(self):
        if not os.path.isfile(SOL_FIXTURE_2):
            self.skipTest("second fixture missing")
        with open(SOL_FIXTURE_2, "rb") as handle:
            other_bytes = handle.read()
        art1 = self._artifact("One.sol")
        art2 = self.service.ingest_upload(other_bytes, "Two.sol")
        a = self.service.run_all(art1["id"])
        b = self.service.run_all(art2["id"])
        with self.assertRaises(HistoryError) as ctx:
            self.service.diff_graphs(a["id"], b["id"])
        self.assertEqual(ctx.exception.code, ERROR_DIFF_MISMATCH)

    def test_missing_scan_rejected(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.diff_graphs(1, 2)
        self.assertEqual(ctx.exception.code, ERROR_NOT_FOUND)

    def test_single_rule_scan_has_no_graph(self):
        art = self._artifact()
        a = self.service.run_all(art["id"])
        b = self.service.run_analysis(art["id"], task_id="11")  # no graph persisted
        diff = self.service.diff_graphs(a["id"], b["id"])
        self.assertFalse(diff["graph_available"])
        self.assertEqual(diff["added_nodes"], [])
        self.assertEqual(diff["removed_nodes"], [])


if __name__ == "__main__":
    unittest.main()

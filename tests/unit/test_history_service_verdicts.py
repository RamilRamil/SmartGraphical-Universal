"""HistoryService finding-verdict tests (feature 013)."""
import os
import tempfile
import unittest

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.persistence.verdict_repository import VerdictRepository
from smartgraphical.services.history_service import (
    ERROR_INVALID_VERDICT,
    HistoryError,
    HistoryService,
    _finding_key_hash,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "WithdrawNoGuard.sol")


class HistoryServiceVerdictTests(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(FIXTURE):
            self.skipTest(f"fixture missing: {FIXTURE}")
        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        self.store = SqliteStore(os.path.join(root, "history.db"))
        self.service = HistoryService(
            store=self.store,
            artifact_repository=ArtifactRepository(self.store),
            scan_repository=ScanRepository(self.store),
            workspace_path=os.path.join(root, "workspace"),
            repo_root=REPO_ROOT,
            verdict_repository=VerdictRepository(self.store),
        )
        with open(FIXTURE, "rb") as handle:
            self.artifact = self.service.ingest_upload(handle.read(), "WithdrawNoGuard.sol")
        self.aid = self.artifact["id"]
        scan = self.service.run_all(self.aid)
        self.scan_id = scan["id"]
        self.findings = self.service.get_scan(self.scan_id)["findings"]
        if not self.findings:
            self.skipTest("fixture produced no findings")
        self.key = self.findings[0]["finding_key"]

    def tearDown(self):
        self._tmp.cleanup()

    def test_findings_enriched_with_key_and_null_verdict(self):
        for finding in self.findings:
            self.assertIn("finding_key", finding)
            self.assertIsNone(finding["verdict"])

    def test_set_verdict_annotates_only_that_finding(self):
        self.service.set_verdict(self.aid, self.key, "false_positive", "noise")
        enriched = self.service.get_scan(self.scan_id)["findings"]
        marked = [f for f in enriched if f["finding_key"] == self.key]
        self.assertTrue(marked)
        for finding in marked:
            self.assertEqual(finding["verdict"]["status"], "false_positive")
            self.assertEqual(finding["verdict"]["note"], "noise")
        for finding in (f for f in enriched if f["finding_key"] != self.key):
            self.assertIsNone(finding["verdict"])

    def test_verdict_survives_rescan(self):
        self.service.set_verdict(self.aid, self.key, "false_positive")
        scan2 = self.service.run_all(self.aid)
        enriched2 = self.service.get_scan(scan2["id"])["findings"]
        marked = [f for f in enriched2 if f["finding_key"] == self.key]
        self.assertTrue(marked, "the same finding should recur in the re-scan")
        self.assertEqual(marked[0]["verdict"]["status"], "false_positive")

    def test_clear_verdict(self):
        self.service.set_verdict(self.aid, self.key, "accepted")
        self.assertEqual(self.service.clear_verdict(self.aid, self.key), {"cleared": True})
        enriched = self.service.get_scan(self.scan_id)["findings"]
        self.assertTrue(
            all(f["verdict"] is None for f in enriched if f["finding_key"] == self.key)
        )

    def test_invalid_status_rejected(self):
        with self.assertRaises(HistoryError) as ctx:
            self.service.set_verdict(self.aid, self.key, "bogus")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_VERDICT)

    def test_list_verdicts(self):
        self.service.set_verdict(self.aid, self.key, "accepted", "ok")
        rows = self.service.list_verdicts(self.aid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "accepted")

    def test_diff_drops_false_positive(self):
        scan_b = self.service.run_analysis(self.aid, task_id="11")
        diff0 = self.service.diff_scans(self.scan_id, scan_b["id"])
        if not diff0["removed"]:
            self.skipTest("no 'removed' delta to suppress in this fixture")
        victim_key = _finding_key_hash(diff0["removed"][0])
        self.service.set_verdict(self.aid, victim_key, "false_positive")
        diff1 = self.service.diff_scans(self.scan_id, scan_b["id"])
        removed_keys = {_finding_key_hash(f) for f in diff1["removed"]}
        self.assertNotIn(victim_key, removed_keys)
        self.assertGreaterEqual(diff1["suppressed_count"], 1)


if __name__ == "__main__":
    unittest.main()

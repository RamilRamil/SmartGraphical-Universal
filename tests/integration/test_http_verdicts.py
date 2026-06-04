"""HTTP contract tests for finding verdict endpoints (feature 013)."""
import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
    from smartgraphical.interfaces.http.app import create_app
    _HTTP_DEPS_AVAILABLE = True
except ImportError:  # pragma: no cover
    TestClient = None  # type: ignore
    create_app = None  # type: ignore
    _HTTP_DEPS_AVAILABLE = False

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.persistence.verdict_repository import VerdictRepository
from smartgraphical.services.history_service import HistoryService

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "WithdrawNoGuard.sol")


@unittest.skipUnless(_HTTP_DEPS_AVAILABLE, "fastapi stack is not installed")
class HttpVerdictTests(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(FIXTURE):
            self.skipTest(f"fixture missing: {FIXTURE}")
        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        store = SqliteStore(os.path.join(root, "history.db"))
        self.service = HistoryService(
            store=store,
            artifact_repository=ArtifactRepository(store),
            scan_repository=ScanRepository(store),
            workspace_path=os.path.join(root, "workspace"),
            repo_root=REPO_ROOT,
            verdict_repository=VerdictRepository(store),
        )
        self.client = TestClient(create_app(self.service, static_dir=None))
        with open(FIXTURE, "rb") as handle:
            artifact = self.service.ingest_upload(handle.read(), "WithdrawNoGuard.sol")
        self.aid = artifact["id"]
        scan = self.service.run_all(self.aid)
        self.scan_id = scan["id"]
        findings = self.client.get(f"/api/scans/{self.scan_id}").json()["findings"]
        if not findings:
            self.skipTest("fixture produced no findings")
        self.key = findings[0]["finding_key"]

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_findings_carry_finding_key_and_verdict(self):
        findings = self.client.get(f"/api/scans/{self.scan_id}").json()["findings"]
        self.assertTrue(all("finding_key" in f and "verdict" in f for f in findings))

    def test_put_get_delete_verdict(self):
        put = self.client.put(
            f"/api/artifacts/{self.aid}/verdicts",
            json={"finding_key": self.key, "status": "false_positive", "note": "noise"},
        )
        self.assertEqual(put.status_code, 200)
        self.assertEqual(put.json()["status"], "false_positive")

        # enriched scan now shows the verdict
        findings = self.client.get(f"/api/scans/{self.scan_id}").json()["findings"]
        marked = [f for f in findings if f["finding_key"] == self.key]
        self.assertTrue(marked and marked[0]["verdict"]["status"] == "false_positive")

        listed = self.client.get(f"/api/artifacts/{self.aid}/verdicts").json()["items"]
        self.assertEqual(len(listed), 1)

        deleted = self.client.delete(f"/api/artifacts/{self.aid}/verdicts/{self.key}")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["cleared"])

    def test_invalid_status_is_400(self):
        resp = self.client.put(
            f"/api/artifacts/{self.aid}/verdicts",
            json={"finding_key": self.key, "status": "bogus"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["code"], "invalid_verdict")

    def test_verdict_for_missing_artifact_is_404(self):
        resp = self.client.put(
            "/api/artifacts/999999/verdicts",
            json={"finding_key": self.key, "status": "accepted"},
        )
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()

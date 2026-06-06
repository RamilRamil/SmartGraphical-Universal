"""HTTP contract test for the graph-diff endpoint (feature 018)."""
import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
    from smartgraphical.interfaces.http.app import create_app
except Exception:  # pragma: no cover - fastapi optional in some envs
    TestClient = None
    create_app = None

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import HistoryService

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")
SOL_NAME = os.path.basename(SOL_FIXTURE)


@unittest.skipUnless(TestClient and create_app, "fastapi not available")
class HttpGraphDiffTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        root = self._tmpdir.name
        store = SqliteStore(os.path.join(root, "history.db"))
        service = HistoryService(
            store=store,
            artifact_repository=ArtifactRepository(store),
            scan_repository=ScanRepository(store),
            workspace_path=os.path.join(root, "workspace"),
            repo_root=REPO_ROOT,
        )
        self.app = create_app(service, static_dir=None)
        self.client = TestClient(self.app)
        if not os.path.isfile(SOL_FIXTURE):
            self.skipTest("solidity fixture missing")
        with open(SOL_FIXTURE, "rb") as handle:
            self._bytes = handle.read()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _upload(self, name=SOL_NAME, data=None):
        r = self.client.post("/api/artifacts", files={"file": (name, data or self._bytes, "text/plain")})
        self.assertEqual(r.status_code, 201, msg=r.text)
        return r.json()

    def _run_all(self, artifact_id):
        r = self.client.post(f"/api/artifacts/{artifact_id}/scans", json={"task": "all", "mode": "auditor"})
        self.assertEqual(r.status_code, 201, msg=r.text)
        return r.json()["id"]

    def test_graph_diff_endpoint_returns_diff(self):
        art = self._upload()
        a = self._run_all(art["id"])
        b = self._run_all(art["id"])
        r = self.client.get(f"/api/scans/{a}/graph-diff/{b}")
        self.assertEqual(r.status_code, 200, msg=r.text)
        body = r.json()
        self.assertTrue(body["graph_available"])
        self.assertEqual(body["added_nodes"], [])
        self.assertEqual(body["removed_nodes"], [])
        self.assertEqual(body["scan_a_id"], a)
        self.assertEqual(body["scan_b_id"], b)
        for key in ("added_node_count", "removed_node_count", "changed_node_count",
                    "added_edge_count", "removed_edge_count", "unchanged_node_count"):
            self.assertIn(key, body)

    def test_graph_diff_rejects_different_artifacts(self):
        art1 = self._upload("One.sol")
        art2 = self._upload("Two.sol", data=self._bytes + b"\n// distinct\n")
        a = self._run_all(art1["id"])
        b = self._run_all(art2["id"])
        r = self.client.get(f"/api/scans/{a}/graph-diff/{b}")
        self.assertGreaterEqual(r.status_code, 400)
        self.assertEqual(r.json().get("code"), "diff_artifact_mismatch")


if __name__ == "__main__":
    unittest.main()

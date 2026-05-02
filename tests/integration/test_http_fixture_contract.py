"""HTTP ingest + scan + findings JSON shape using a checked-in Solidity fixture.

Avoids relying on SimpleAuction.sol at repo root for this contract (phase 3).
"""
import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
    from smartgraphical.interfaces.http.app import create_app
    _HTTP_DEPS_AVAILABLE = True
except ImportError:  # pragma: no cover - dev env without web extras
    TestClient = None  # type: ignore
    create_app = None  # type: ignore
    _HTTP_DEPS_AVAILABLE = False
from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import HistoryService


TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(TESTS_DIR)
FIXTURE_PATH = os.path.join(TESTS_DIR, "fixtures", "solidity", "MinimalGuard.sol")


@unittest.skipUnless(_HTTP_DEPS_AVAILABLE, "fastapi stack is not installed")
class HttpFixtureContractTests(unittest.TestCase):
    """End-to-end shape checks for REST responses after analyzing a fixture file."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(FIXTURE_PATH):
            raise unittest.SkipTest(f"Missing fixture {FIXTURE_PATH}")
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._root = cls._tmpdir.name
        db_path = os.path.join(cls._root, "history.db")
        store = SqliteStore(db_path)
        service = HistoryService(
            store=store,
            artifact_repository=ArtifactRepository(store),
            scan_repository=ScanRepository(store),
            workspace_path=os.path.join(cls._root, "workspace"),
            repo_root=REPO_ROOT,
        )
        cls.app = create_app(service, static_dir=None)
        with open(FIXTURE_PATH, "rb") as handle:
            cls._fixture_bytes = handle.read()

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()

    def setUp(self):
        self.client = TestClient(self.app)

    def _upload_fixture(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": ("MinimalGuard.sol", self._fixture_bytes, "text/plain")},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        return response.json()

    def test_scan_all_then_findings_and_scan_payload_shape(self):
        artifact = self._upload_fixture()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "all", "mode": "auditor"},
        )
        self.assertEqual(created.status_code, 201, msg=created.text)
        scan = created.json()

        findings_resp = self.client.get(f"/api/scans/{scan['id']}/findings")
        self.assertEqual(findings_resp.status_code, 200)
        findings_body = findings_resp.json()
        self.assertIn("items", findings_body)
        self.assertIsInstance(findings_body["items"], list)
        for item in findings_body["items"]:
            for key in ("rule_id", "task_id", "title", "message", "evidences"):
                self.assertIn(key, item)

        detail_resp = self.client.get(f"/api/scans/{scan['id']}")
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertIn("scan", detail)
        self.assertIn("findings", detail)
        self.assertIsInstance(detail["findings"], list)


if __name__ == "__main__":
    unittest.main()

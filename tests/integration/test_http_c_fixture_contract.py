"""HTTP ingest + scan + findings JSON shape using a checked-in .c fixture."""

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
FIXTURE_PATH = os.path.join(TESTS_DIR, "fixtures", "c", "MinimalTu.c")


@unittest.skipUnless(_HTTP_DEPS_AVAILABLE, "fastapi stack is not installed")
class HttpCFixtureContractTests(unittest.TestCase):
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

    def _upload(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": ("MinimalTu.c", self._fixture_bytes, "text/plain")},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        body = response.json()
        self.assertEqual(body["language"], "c")
        return body

    def test_scan_all_then_findings_shape(self):
        artifact = self._upload()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "all", "mode": "auditor"},
        )
        self.assertEqual(created.status_code, 201, msg=created.text)
        scan = created.json()

        findings_resp = self.client.get(f"/api/scans/{scan['id']}/findings")
        self.assertEqual(findings_resp.status_code, 200)
        body = findings_resp.json()
        self.assertIn("items", body)
        self.assertIsInstance(body["items"], list)
        for item in body["items"]:
            for key in ("rule_id", "task_id", "title", "message", "evidences"):
                self.assertIn(key, item)


if __name__ == "__main__":
    unittest.main()

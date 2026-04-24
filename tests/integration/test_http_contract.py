"""Integration tests for the FastAPI HTTP layer.

These tests spin up a real FastAPI app wired to real HistoryService and
SQLite (in a temp directory) so the HTTP contract is validated end-to-end
against the same stack that will serve the frontend.
"""
import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from smartgraphical.interfaces.http.app import create_app
from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import HistoryService


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class HttpContractTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._root = self._tmpdir.name
        db_path = os.path.join(self._root, "history.db")
        store = SqliteStore(db_path)
        service = HistoryService(
            store=store,
            artifact_repository=ArtifactRepository(store),
            scan_repository=ScanRepository(store),
            workspace_path=os.path.join(self._root, "workspace"),
            repo_root=REPO_ROOT,
        )
        self.app = create_app(service, static_dir=None)
        self.client = TestClient(self.app)
        with open(SIMPLE_AUCTION_PATH, "rb") as handle:
            self._source_bytes = handle.read()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _upload_artifact(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": ("SimpleAuction.sol", self._source_bytes, "text/plain")},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        return response.json()

    def test_health_returns_ok(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertIn("solidity", payload["supported_languages"])

    def test_tasks_for_solidity(self):
        response = self.client.get("/api/languages/solidity/tasks")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["language"], "solidity")
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("11", ids)
        self.assertEqual(ids[-1], "all")

    def test_tasks_for_unknown_language(self):
        response = self.client.get("/api/languages/rust/tasks")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_language")

    def test_openapi_is_exposed(self):
        response = self.client.get("/api/openapi.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("paths", response.json())

    def test_upload_artifact_success(self):
        artifact = self._upload_artifact()
        self.assertIn("id", artifact)
        self.assertEqual(artifact["language"], "solidity")

    def test_upload_artifact_dedups(self):
        first = self._upload_artifact()
        second = self._upload_artifact()
        self.assertEqual(first["id"], second["id"])

    def test_upload_rejects_empty_payload(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": ("empty.sol", b"", "text/plain")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_payload")

    def test_upload_rejects_unsupported_extension(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": ("danger.exe", b"MZ\x00\x00", "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "unsupported_file")

    def test_list_artifacts_returns_uploaded_entries(self):
        artifact = self._upload_artifact()
        response = self.client.get("/api/artifacts")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["id"], artifact["id"])

    def test_get_artifact_not_found(self):
        response = self.client.get("/api/artifacts/9999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "not_found")

    def test_create_scan_with_task(self):
        artifact = self._upload_artifact()
        response = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11", "mode": "auditor"},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        scan = response.json()
        self.assertEqual(scan["task"], "11")
        self.assertEqual(scan["status"], "ok")

    def test_create_scan_all(self):
        artifact = self._upload_artifact()
        response = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "all", "mode": "auditor"},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        scan = response.json()
        self.assertEqual(scan["task"], "all")

    def test_create_scan_rejects_invalid_task(self):
        artifact = self._upload_artifact()
        response = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "9999", "mode": "auditor"},
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertTrue(body["error_code"])

    def test_create_scan_rejects_unknown_artifact(self):
        response = self.client.post(
            "/api/artifacts/9999/scans",
            json={"task": "11", "mode": "auditor"},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "not_found")

    def test_get_scan_returns_combined_view(self):
        artifact = self._upload_artifact()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11"},
        ).json()
        response = self.client.get(f"/api/scans/{created['id']}")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scan"]["id"], created["id"])
        self.assertEqual(payload["artifact"]["id"], artifact["id"])
        self.assertIsInstance(payload["findings"], list)

    def test_findings_endpoint(self):
        artifact = self._upload_artifact()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11"},
        ).json()
        response = self.client.get(f"/api/scans/{created['id']}/findings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("items", response.json())

    def test_graph_endpoint_reports_unavailable_for_task_scan(self):
        artifact = self._upload_artifact()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11"},
        ).json()
        response = self.client.get(f"/api/scans/{created['id']}/graph")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["available"])

    def test_graph_endpoint_returns_payload_for_all_scan(self):
        artifact = self._upload_artifact()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "all"},
        ).json()
        response = self.client.get(f"/api/scans/{created['id']}/graph")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["available"])
        self.assertIn("graph", payload)

    def test_diff_scans_same_artifact(self):
        artifact = self._upload_artifact()
        scan_a = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11"},
        ).json()
        scan_b = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "all"},
        ).json()
        response = self.client.get(f"/api/scans/{scan_a['id']}/diff/{scan_b['id']}")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["artifact_id"], artifact["id"])
        self.assertIn("added", payload)
        self.assertIn("removed", payload)

    def test_diff_scans_different_artifacts_returns_conflict(self):
        artifact_one = self._upload_artifact()
        response = self.client.post(
            "/api/artifacts",
            files={
                "file": (
                    "Other.sol",
                    self._source_bytes + b"\n// padding\n",
                    "text/plain",
                ),
            },
        )
        artifact_two = response.json()
        scan_a = self.client.post(
            f"/api/artifacts/{artifact_one['id']}/scans",
            json={"task": "11"},
        ).json()
        scan_b = self.client.post(
            f"/api/artifacts/{artifact_two['id']}/scans",
            json={"task": "11"},
        ).json()
        diff = self.client.get(f"/api/scans/{scan_a['id']}/diff/{scan_b['id']}")
        self.assertEqual(diff.status_code, 409)
        self.assertEqual(diff.json()["code"], "diff_artifact_mismatch")

    def test_soft_delete_scan(self):
        artifact = self._upload_artifact()
        created = self.client.post(
            f"/api/artifacts/{artifact['id']}/scans",
            json={"task": "11"},
        ).json()
        response = self.client.delete(f"/api/scans/{created['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["deleted"])
        follow_up = self.client.get(f"/api/scans/{created['id']}")
        self.assertEqual(follow_up.status_code, 404)

    def test_list_scans_filters_by_artifact(self):
        artifact = self._upload_artifact()
        self.client.post(f"/api/artifacts/{artifact['id']}/scans", json={"task": "11"})
        self.client.post(f"/api/artifacts/{artifact['id']}/scans", json={"task": "10"})
        response = self.client.get(f"/api/scans?artifact_id={artifact['id']}")
        self.assertEqual(response.status_code, 200)
        items = response.json()["items"]
        self.assertEqual(len(items), 2)


if __name__ == "__main__":
    unittest.main()

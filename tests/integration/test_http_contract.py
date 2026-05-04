"""Integration tests for the FastAPI HTTP layer.

These tests spin up a real FastAPI app wired to real HistoryService and
SQLite (in a temp directory) so the HTTP contract is validated end-to-end
against the same stack that will serve the frontend.
"""
import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
    from smartgraphical.interfaces.http.app import create_app
    _HTTP_DEPS_AVAILABLE = True
except ImportError:  # pragma: no cover - env without web extras
    TestClient = None  # type: ignore
    create_app = None  # type: ignore
    _HTTP_DEPS_AVAILABLE = False

from smartgraphical.persistence.artifact_repository import ArtifactRepository
from smartgraphical.persistence.scan_repository import ScanRepository
from smartgraphical.persistence.sqlite_store import SqliteStore
from smartgraphical.services.history_service import HistoryService


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")
FIXTURE_SOL_NAME = os.path.basename(SOL_FIXTURE)


@unittest.skipUnless(_HTTP_DEPS_AVAILABLE, "fastapi stack is not installed")
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
        if not os.path.isfile(SOL_FIXTURE):
            self.skipTest(f"solidity fixture missing: {SOL_FIXTURE}")
        with open(SOL_FIXTURE, "rb") as handle:
            self._source_bytes = handle.read()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _upload_artifact(self):
        response = self.client.post(
            "/api/artifacts",
            files={"file": (FIXTURE_SOL_NAME, self._source_bytes, "text/plain")},
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        return response.json()

    def test_health_returns_ok(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        langs = payload["supported_languages"]
        self.assertIn("solidity", langs)
        self.assertIn("c", langs)
        self.assertIn("rust", langs)

    def test_tasks_for_solidity(self):
        response = self.client.get("/api/languages/solidity/tasks")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["language"], "solidity")
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("11", ids)
        self.assertEqual(ids[-1], "all")

    def test_tasks_for_rust(self):
        response = self.client.get("/api/languages/rust/tasks")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["language"], "rust")
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("216", ids)
        self.assertEqual(ids[-1], "all")

    def test_tasks_for_unknown_language(self):
        response = self.client.get("/api/languages/go/tasks")
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

    def test_upload_artifacts_batch_two_files(self):
        path_b = os.path.join(
            REPO_ROOT, "tests", "fixtures", "solidity", "ExternalMint.sol",
        )
        self.assertTrue(os.path.isfile(path_b), msg=path_b)
        with open(path_b, "rb") as fh:
            bytes_b = fh.read()
        response = self.client.post(
            "/api/artifacts/batch",
            files=[
                ("files", (FIXTURE_SOL_NAME, self._source_bytes, "text/plain")),
                ("files", ("ExternalMint.sol", bytes_b, "text/plain")),
            ],
        )
        self.assertEqual(response.status_code, 200, msg=response.text)
        payload = response.json()
        self.assertEqual(payload["summary"]["ok"], 2)
        self.assertEqual(payload["summary"]["error"], 0)
        self.assertEqual(len(payload["items"]), 2)
        self.assertTrue(payload["items"][0]["ok"])
        self.assertTrue(payload["items"][1]["ok"])
        self.assertNotEqual(
            payload["items"][0]["artifact"]["id"],
            payload["items"][1]["artifact"]["id"],
        )

    def test_upload_artifacts_batch_partial_failure(self):
        response = self.client.post(
            "/api/artifacts/batch",
            files=[
                ("files", (FIXTURE_SOL_NAME, self._source_bytes, "text/plain")),
                ("files", ("bad.exe", b"MZ\x00\x00", "application/octet-stream")),
            ],
        )
        self.assertEqual(response.status_code, 200, msg=response.text)
        payload = response.json()
        self.assertEqual(payload["summary"]["ok"], 1)
        self.assertEqual(payload["summary"]["error"], 1)
        self.assertTrue(payload["items"][0]["ok"])
        self.assertFalse(payload["items"][1]["ok"])
        self.assertEqual(payload["items"][1]["code"], "unsupported_file")

    def test_upload_artifacts_batch_rejects_empty(self):
        response = self.client.post("/api/artifacts/batch", files=[])
        self.assertIn(response.status_code, (400, 422), msg=response.text)

    def test_upload_artifacts_bundle_two_sol_merged_graph(self):
        path_b = os.path.join(
            REPO_ROOT, "tests", "fixtures", "solidity", "ExternalMint.sol",
        )
        self.assertTrue(os.path.isfile(path_b), msg=path_b)
        with open(path_b, "rb") as fh:
            bytes_b = fh.read()
        response = self.client.post(
            "/api/artifacts/bundle",
            files=[
                ("files", (FIXTURE_SOL_NAME, self._source_bytes, "text/plain")),
                ("files", ("ExternalMint.sol", bytes_b, "text/plain")),
            ],
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        art = response.json()
        self.assertTrue(os.path.isdir(art["path_on_disk"]))
        man = os.path.join(art["path_on_disk"], "sg_bundle_manifest.json")
        self.assertTrue(os.path.isfile(man))
        scan_r = self.client.post(
            f"/api/artifacts/{art['id']}/scans",
            json={"task": "all", "mode": "auditor"},
        )
        self.assertEqual(scan_r.status_code, 201, msg=scan_r.text)
        scan_id = scan_r.json()["id"]
        graph_r = self.client.get(f"/api/scans/{scan_id}/graph")
        self.assertEqual(graph_r.status_code, 200)
        body = graph_r.json()
        self.assertTrue(body.get("available"))
        ms = body["graph"]["model_summary"]
        self.assertIn("bundle_members", (ms.get("artifact") or {}))
        nodes = (ms.get("graph") or {}).get("nodes") or []
        tags = {n.get("source_file") for n in nodes if n.get("source_file")}
        self.assertIn(FIXTURE_SOL_NAME, tags)
        self.assertIn("ExternalMint.sol", tags)

    def test_upload_artifacts_bundle_rejects_mixed_language(self):
        path_c = os.path.join(REPO_ROOT, "tests", "fixtures", "c", "MinimalTu.c")
        if not os.path.isfile(path_c):
            self.skipTest(f"missing {path_c}")
        with open(path_c, "rb") as fh:
            c_bytes = fh.read()
        response = self.client.post(
            "/api/artifacts/bundle",
            files=[
                ("files", (FIXTURE_SOL_NAME, self._source_bytes, "text/plain")),
                ("files", ("MinimalTu.c", c_bytes, "text/plain")),
            ],
        )
        self.assertEqual(response.status_code, 400, msg=response.text)
        self.assertEqual(response.json().get("code"), "invalid_payload")

    def test_upload_artifacts_bundle_c_h_header_edge_in_graph(self):
        user_src = (
            b'#include "dep.h"\n'
            b"static void u(void) { (void)0; }\n"
        )
        dep_h = b"#ifndef DEP_H\n#define DEP_H\n#endif\n"
        response = self.client.post(
            "/api/artifacts/bundle",
            files=[
                ("files", ("dep.h", dep_h, "text/plain")),
                ("files", ("user.c", user_src, "text/plain")),
            ],
        )
        self.assertEqual(response.status_code, 201, msg=response.text)
        art = response.json()
        scan_r = self.client.post(
            f"/api/artifacts/{art['id']}/scans",
            json={"task": "all", "mode": "auditor"},
        )
        self.assertEqual(scan_r.status_code, 201, msg=scan_r.text)
        scan_id = scan_r.json()["id"]
        graph_r = self.client.get(f"/api/scans/{scan_id}/graph")
        self.assertEqual(graph_r.status_code, 200)
        edges = (graph_r.json()["graph"]["model_summary"].get("graph") or {}).get("edges") or []
        bundle_edges = [
            e for e in edges
            if e.get("kind") == "tile_to_tile" and e.get("label") == "bundle_member_include"
        ]
        self.assertEqual(len(bundle_edges), 1, msg=bundle_edges)

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

"""Feature 016: lock the web_api thin-facade re-export contract.

After decomposing web_api.py into bundle_graph / task_catalog / analyze_facade
(+ web_support), web_api must remain the stable public entry point. Every symbol
previously importable from it MUST still resolve, with identical identity for the
error contract. See specs/016-decompose-web-api/contracts/facade.md.
"""
import importlib
import unittest


class WebApiFacadeReexportTests(unittest.TestCase):
    def setUp(self):
        self.web_api = importlib.import_module("smartgraphical.services.web_api")

    def test_public_functions_importable(self):
        for name in ("health", "list_tasks", "analyze", "analyze_all", "graph",
                     "is_run_all_task"):
            self.assertTrue(
                callable(getattr(self.web_api, name, None)),
                f"web_api.{name} must be a callable re-export",
            )

    def test_error_contract_importable(self):
        for name in ("WebApiError", "ERROR_INVALID_PATH", "ERROR_INVALID_LANGUAGE",
                     "ERROR_INVALID_TASK", "ERROR_INVALID_MODE", "ERROR_INTERNAL"):
            self.assertTrue(
                hasattr(self.web_api, name),
                f"web_api.{name} must remain importable",
            )

    def test_private_helpers_still_reexported(self):
        # These underscore helpers are imported by other modules/tests.
        for name in ("_solidity_file_import_paths", "_rust_collect_module_links"):
            self.assertTrue(
                callable(getattr(self.web_api, name, None)),
                f"web_api.{name} must stay importable (external consumers depend on it)",
            )

    def test_webapierror_identity_is_shared(self):
        from smartgraphical.services.web_support import WebApiError as Owner
        self.assertIs(self.web_api.WebApiError, Owner)

    def test_error_sentinel_values_unchanged(self):
        self.assertEqual(self.web_api.ERROR_INVALID_LANGUAGE, "invalid_language")
        self.assertEqual(self.web_api.ERROR_INVALID_PATH, "invalid_path")
        self.assertEqual(self.web_api.ERROR_INTERNAL, "internal_error")

    def test_facade_raises_web_api_webapierror_on_bad_path(self):
        # The error raised by relocated facade code is catchable as
        # web_api.WebApiError, and carries the stable code.
        with self.assertRaises(self.web_api.WebApiError) as ctx:
            self.web_api.analyze("/no/such/file.sol", "1")
        self.assertEqual(ctx.exception.code, self.web_api.ERROR_INVALID_PATH)

    def test_all_declared(self):
        self.assertIn("graph", self.web_api.__all__)
        self.assertIn("WebApiError", self.web_api.__all__)


if __name__ == "__main__":
    unittest.main()

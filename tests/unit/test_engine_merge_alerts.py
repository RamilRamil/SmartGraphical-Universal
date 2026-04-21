"""Tests for engine.merge_alerts: the shared alert deduplication helper."""
import unittest

from smartgraphical.core.engine import merge_alerts


class MergeAlertsTests(unittest.TestCase):

    def test_empty_inputs_return_empty_list(self):
        self.assertEqual(merge_alerts(), [])
        self.assertEqual(merge_alerts([], []), [])

    def test_single_group_preserves_order(self):
        group = [
            {"code": 1, "message": "first"},
            {"code": 2, "message": "second"},
            {"code": 3, "message": "third"},
        ]
        merged = merge_alerts(group)
        self.assertEqual([m["message"] for m in merged], ["first", "second", "third"])

    def test_duplicate_alerts_across_groups_are_removed(self):
        group_a = [{"code": 8, "message": "same message"}]
        group_b = [{"code": 8, "message": "same message"}]
        merged = merge_alerts(group_a, group_b)
        self.assertEqual(len(merged), 1)

    def test_same_message_with_different_code_is_kept(self):
        merged = merge_alerts(
            [{"code": 1, "message": "alert"}],
            [{"code": 2, "message": "alert"}],
        )
        self.assertEqual(len(merged), 2)

    def test_message_newlines_are_normalized_to_space(self):
        merged = merge_alerts([{"code": 1, "message": "line_a\nline_b"}])
        self.assertEqual(len(merged), 1)
        self.assertNotIn("\n", merged[0]["message"])
        self.assertIn("line_a", merged[0]["message"])
        self.assertIn("line_b", merged[0]["message"])

    def test_leading_trailing_whitespace_is_trimmed(self):
        merged = merge_alerts([{"code": 1, "message": "   padded   "}])
        self.assertEqual(merged[0]["message"], "padded")

    def test_dedupe_is_based_on_normalized_message(self):
        merged = merge_alerts(
            [{"code": 1, "message": "hello\nworld"}],
            [{"code": 1, "message": "hello world"}],
        )
        self.assertEqual(len(merged), 1)

    def test_missing_fields_do_not_crash(self):
        merged = merge_alerts([{"code": 1}])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["message"], "")

    def test_order_preserved_across_groups(self):
        merged = merge_alerts(
            [{"code": 1, "message": "a"}, {"code": 1, "message": "b"}],
            [{"code": 1, "message": "c"}],
        )
        self.assertEqual([m["message"] for m in merged], ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()

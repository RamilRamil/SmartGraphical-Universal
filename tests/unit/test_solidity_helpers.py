"""Focused unit tests for low-level Solidity parsing helpers."""
import unittest

from smartgraphical.adapters.solidity.helpers import (
    comment_remover,
    extract_asserts,
    extract_requirements,
    find_uniques,
    intra_contract_connection,
    remove_extra_spaces,
    similar_string,
)


class CommentRemoverTests(unittest.TestCase):

    def test_line_comment_is_stripped(self):
        cleaned = comment_remover("x = 1; // trailing note")
        self.assertNotIn("trailing note", cleaned)
        self.assertIn("x = 1;", cleaned)

    def test_block_comment_is_stripped(self):
        cleaned = comment_remover("a /* secret */ b")
        self.assertNotIn("secret", cleaned)
        self.assertIn("a", cleaned)
        self.assertIn("b", cleaned)

    def test_string_literals_are_preserved(self):
        cleaned = comment_remover('msg = "http://example"; // note')
        self.assertIn('"http://example"', cleaned)


class RemoveExtraSpacesTests(unittest.TestCase):

    def test_collapses_repeated_whitespace(self):
        self.assertEqual(remove_extra_spaces("a   b    c"), "a b c")

    def test_trims_leading_and_trailing(self):
        self.assertEqual(remove_extra_spaces("   a b   "), "a b")


class SimilarStringTests(unittest.TestCase):

    def test_finds_close_match(self):
        match = similar_string("totalSupply", ["totalSupplyX", "balance", "fee"])
        self.assertEqual(match, "totalSupplyX")

    def test_returns_none_when_nothing_close(self):
        self.assertIsNone(similar_string("xxxxxx", ["yyyyyy", "zzzzzz"]))


class ExtractRequirementsTests(unittest.TestCase):

    def test_single_require_is_extracted(self):
        body = "require(x > 0); a = 1;"
        self.assertEqual(extract_requirements([body]), [["require(x > 0);"]])

    def test_multiple_requires_are_extracted_in_order(self):
        body = "require(a); do_something(); require(b);"
        result = extract_requirements([body])[0]
        self.assertEqual(len(result), 2)
        self.assertTrue(result[0].startswith("require(a"))
        self.assertTrue(result[1].startswith("require(b"))

    def test_no_requires_returns_empty_inner_list(self):
        self.assertEqual(extract_requirements(["no checks here;"]), [[]])


class ExtractAssertsTests(unittest.TestCase):

    def test_single_assert_is_extracted(self):
        body = "assert(x == 1); do_it();"
        self.assertEqual(extract_asserts([body]), [["assert(x == 1);"]])

    def test_no_asserts_returns_empty_inner_list(self):
        self.assertEqual(extract_asserts(["do_it();"]), [[]])


class FindUniquesTests(unittest.TestCase):

    def test_preserves_first_occurrence_order(self):
        self.assertEqual(find_uniques(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

    def test_empty_input(self):
        self.assertEqual(find_uniques([]), [])


class IntraContractConnectionTests(unittest.TestCase):

    def test_returns_true_when_function_is_used_elsewhere(self):
        high_connections = [
            {"func_func_mapping": {"caller": ["bid"]}},
        ]
        self.assertTrue(intra_contract_connection(high_connections, "bid"))

    def test_returns_false_when_function_not_found(self):
        high_connections = [
            {"func_func_mapping": {"caller": ["other"]}},
        ]
        self.assertFalse(intra_contract_connection(high_connections, "bid"))

    def test_returns_false_on_empty_connections(self):
        self.assertFalse(intra_contract_connection([], "bid"))


if __name__ == "__main__":
    unittest.main()

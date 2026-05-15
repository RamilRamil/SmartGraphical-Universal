"""Regression: line inference for findings when statement spacing differs from source."""
import os
import tempfile
import unittest
from pathlib import Path

from smartgraphical.core.engine import _infer_line_numbers
from smartgraphical.core.model import NormalizedArtifact, NormalizedAuditModel


class EngineLineNumbersTests(unittest.TestCase):
    def test_exact_substring_match(self):
        fd, p = tempfile.mkstemp(suffix=".sol")
        os.close(fd)
        try:
            Path(p).write_text(
                "contract C {\n"
                "  function f() public {\n"
                "    uint256 x = a * b / c;\n"
                "  }\n"
                "}\n",
                encoding="ascii",
            )
            art = NormalizedArtifact(path=p, language="solidity", adapter_name="t")
            model = NormalizedAuditModel(artifact=art)
            nums = _infer_line_numbers(model, "uint256 x = a * b / c;")
            self.assertIn(3, nums)
        finally:
            os.remove(p)

    def test_whitespace_collapsed_match(self):
        fd, p = tempfile.mkstemp(suffix=".sol")
        os.close(fd)
        try:
            Path(p).write_text(
                "contract C {\n"
                "  function f() public {\n"
                "    uint256 x = a * b / c;\n"
                "  }\n"
                "}\n",
                encoding="ascii",
            )
            art = NormalizedArtifact(path=p, language="solidity", adapter_name="t")
            model = NormalizedAuditModel(artifact=art)
            # Extra spaces like normalized extraction might produce
            nums = _infer_line_numbers(model, "uint256  x =  a * b / c;")
            self.assertIn(3, nums)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()

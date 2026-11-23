"""Pinned family inventory tokens must match scripts/extract_line_start_tokens.py."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "notes" / "family-source-inventory.json"
SCRIPT = ROOT / "scripts" / "extract_line_start_tokens.py"
SOURCES = ROOT / "notes" / "pinned-sources"

sys.path.insert(0, str(ROOT / "scripts"))
from extract_line_start_tokens import extract_tokens  # noqa: E402


class LineStartTokenTests(unittest.TestCase):
    def test_noncomputable_def_is_captured(self):
        sample = "noncomputable def foo : Nat := 0\n"
        self.assertEqual(extract_tokens(sample), ["foo"])
    def test_inventory_matches_extraction_script(self):
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        computed = json.loads(result.stdout)
        for record in inventory["records"]:
            path = record["path"]
            self.assertIn(
                "line_start_tokens",
                record,
                f"record missing line_start_tokens: {path}",
            )
            stored = record["line_start_tokens"]
            self.assertEqual(
                len(stored),
                len(set(stored)),
                f"duplicate tokens in inventory for {path}",
            )
            self.assertEqual(
                stored,
                computed[path],
                f"drift for {path}: stored vs script",
            )

    def test_pinned_sources_present(self):
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        for record in inventory["records"]:
            lean = SOURCES / record["path"]
            self.assertTrue(lean.is_file(), f"missing pinned file {lean}")


if __name__ == "__main__":
    unittest.main()
"""Byte-for-byte pin regeneration from inventory_erdos.py."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "inventory_erdos.py"
PIN = ROOT / "notes" / "openai-math-erdos-build.json"
CONTENTS = Path(__file__).parent / "fixtures" / "openai-math-CONTENTS.md"
TOOLCHAIN = Path(__file__).parent / "fixtures" / "openai-math-lean-toolchain"
SOURCE_COMMIT = "7ef5c0cc5ca4b0e072b7a050fca09ab24bc6fa3a"


class InventoryErdosTests(unittest.TestCase):
    def test_pin_matches_script_output_byte_for_byte(self):
        expected = PIN.read_bytes()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(CONTENTS),
                "--commit",
                SOURCE_COMMIT,
                "--toolchain",
                str(TOOLCHAIN),
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
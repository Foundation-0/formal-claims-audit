#!/usr/bin/env python3
"""Replay the frozen pre-repair control without importing the invalid CLI tail."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / "repo/scripts").mkdir(parents=True)
    (root / "output").mkdir()
    shutil.copyfile(HERE / "submitted-auditor.py.txt", root / "repo/scripts/audit_python_checkers.py")
    shutil.copyfile(HERE / "reproduce_scope.py", root / "output/reproduce_scope.py")
    result = subprocess.run([sys.executable, str(root / "output/reproduce_scope.py")],
                            check=True, text=True, capture_output=True)
    observed = json.loads(result.stdout)
    expected = json.loads((HERE / "scope-results.json").read_text())
    if observed != expected:
        raise SystemExit("Original scope counterexample replay differs from its frozen output")
    print("Original counterexamples reproduced. This does not execute the submitted CLI.")

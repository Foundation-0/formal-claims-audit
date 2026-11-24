"""Revert demos: round-5 p16r4 controls must fail against audit_python_checkers @ 704d308d."""
from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

DEFAULT_REVERT = Path("/opt/cursor/artifacts/audit_704d308d.py")
REVERT_PATH = Path(os.environ.get("AUDIT_REVERT_REF", DEFAULT_REVERT))


def _load_apc():
    spec = importlib.util.spec_from_file_location(
        "audit_python_checkers_revert", REVERT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load revert auditor from {REVERT_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P16 = Path(__file__).resolve().parent / "fixtures" / "p16r4"


@unittest.skipUnless(
    REVERT_PATH.is_file(),
    "revert auditor snapshot missing (generate for REVERT-DEMOS only)",
)
class Round5RevertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.apc = _load_apc()
        self.VERDICT_FAIL = self.apc.VERDICT_FAIL

    def _dual(self, left: str, right: str):
        spec_path = P16 / left
        impl_path = P16 / right
        return self.apc.audit_dual_checkers(
            spec_path.read_text(encoding="utf-8"),
            impl_path.read_text(encoding="utf-8"),
            spec_path=spec_path,
            impl_path=impl_path,
        )

    def _single(self, name: str):
        path = P16 / name
        return self.apc.audit_checker_source(path.read_text(encoding="utf-8"), label=str(path))

    def test_dual_andtrue_still_evades_old(self) -> None:
        rep = self._dual("base.py", "n_andtrue.py")
        self.assertEqual(rep["verdict"], self.apc.VERDICT_DISTINCT_LINT_CLEAN)

    def test_getattr_math_still_clean_old(self) -> None:
        self.assertTrue(self._single("s_getattr.py")["clean"])

    def test_fraction_local_alias_false_positive_old(self) -> None:
        rules = {f["rule"] for f in self._single("fp_localalias.py")["findings"]}
        self.assertIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)


if __name__ == "__main__":
    unittest.main()
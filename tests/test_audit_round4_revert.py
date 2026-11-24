"""Revert demos: round-4 p16r3 controls must fail against audit_python_checkers @ 79cfa484."""
from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVERT_PATH = Path(
    os.environ.get(
        "AUDIT_REVERT_REF",
        "/opt/cursor/artifacts/audit_79cfa484.py",
    ),
)


def _load_apc():
    spec = importlib.util.spec_from_file_location(
        "audit_python_checkers_revert", REVERT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load revert auditor from {REVERT_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
P16 = Path(__file__).resolve().parent / "fixtures" / "p16r3"


@unittest.skipUnless(
    REVERT_PATH.is_file(),
    "revert auditor snapshot missing (generate for REVERT-DEMOS only)",
)
class Round4RevertTests(unittest.TestCase):
  """Same expectations as P16R3Round4Tests but against the old auditor (should all error)."""

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

  def test_dual_noop_cosmetics_fail(self) -> None:
    rep = self._dual("base.py", "noop_two.py")
    self.assertEqual(rep["verdict"], self.VERDICT_FAIL)

  def test_dual_dynamic_import_fail(self) -> None:
    rep = self._dual("wrap_c.py", "wrap_d.py")
    self.assertEqual(rep["verdict"], self.VERDICT_FAIL)

  def test_dual_shared_pkg_import_fail(self) -> None:
    rep = self._dual("wrap_e.py", "wrap_f.py")
    self.assertEqual(rep["verdict"], self.VERDICT_FAIL)

  def test_dual_local_module_vs_inline_fail(self) -> None:
    rep = self._dual("wrap_a.py", "base.py")
    self.assertEqual(rep["verdict"], self.VERDICT_FAIL)

  def test_math_import_alias_flagged(self) -> None:
    rules = {f["rule"] for f in self._single("m2.py")["findings"]}
    self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

  def test_cmath_flagged(self) -> None:
    rules = {f["rule"] for f in self._single("m4.py")["findings"]}
    self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

  def test_pow_negative_exponent_flagged(self) -> None:
    rules = {f["rule"] for f in self._single("m8.py")["findings"]}
    self.assertIn("FLOAT_NEGATIVE_EXPONENT", rules)

  def test_fraction_alias_division_clean(self) -> None:
    self.assertTrue(self._single("f2.py")["clean"])


if __name__ == "__main__":
  unittest.main()
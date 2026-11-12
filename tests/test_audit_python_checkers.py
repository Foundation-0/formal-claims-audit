from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_python_checkers import audit_checker_source, audit_dual_checkers


class AuditPythonCheckersTests(unittest.TestCase):
    def test_rejects_alpha_renamed_copy_paste_checkers(self) -> None:
        spec = "def check(state, step):\n    return state + step == 4\n"
        alpha_copy = "def verify(x, mv):\n    return x + mv == 4\n"
        rep = audit_dual_checkers(spec, alpha_copy)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_accepts_genuinely_distinct_exact_checkers(self) -> None:
        spec = "def check(items):\n    return len(frozenset(items)) == 3\n"
        impl = (
            "def check_mask(items):\n"
            "    mask = 0\n"
            "    for v in items:\n"
            "        mask |= (1 << v)\n"
            "    return bin(mask).count('1') == 3\n"
        )
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "PASS")
        self.assertTrue(rep["distinct_alpha_skeleton"])

    def test_catches_optimistic_true_default_f01_and_floats(self) -> None:
        buggy = (
            "def verify_dual(py_ok, cpp_res):\n"
            "    differential_match = True\n"
            "    if cpp_res is not None:\n"
            "        differential_match = (cpp_res == py_ok)\n"
            "    tol = 0.001 / 2\n"
            "    return py_ok and differential_match\n"
        )
        rep = audit_checker_source(buggy, label="buggy.py")
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)
        self.assertIn("FLOAT_LITERAL_IN_EXACT_CHECKER", rules)
        self.assertIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)


if_ __name__ == "__main__":
    unittest.main()

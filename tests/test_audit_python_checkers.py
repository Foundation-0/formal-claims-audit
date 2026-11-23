from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_python_checkers import (  # noqa: E402
    alpha_skeleton_sha256,
    audit_checker_source,
    audit_dual_checkers,
)


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

    # --- Review controls: dual-checker evasions must FAIL (not independent) ---

    def test_dual_evasion_leading_pass_same_skeleton(self) -> None:
        spec = "def check(state, step):\n    return state + step == 4\n"
        impl = "def verify(x, mv):\n    pass\n    return x + mv == 4\n"
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_evasion_commuted_add(self) -> None:
        spec = "def check(x, mv):\n    return x + mv == 4\n"
        impl = "def check(x, mv):\n    return mv + x == 4\n"
        self.assertEqual(
            alpha_skeleton_sha256(spec),
            alpha_skeleton_sha256(impl),
        )

    def test_dual_evasion_commuted_eq(self) -> None:
        spec = "def check(x, mv):\n    return x + mv == 4\n"
        impl = "def check(x, mv):\n    return 4 == x + mv\n"
        self.assertEqual(
            alpha_skeleton_sha256(spec),
            alpha_skeleton_sha256(impl),
        )

    def test_dual_evasion_temp_variable(self) -> None:
        spec = "def check(x, mv):\n    return x + mv == 4\n"
        impl = "def check(x, mv):\n    t = x + mv\n    return t == 4\n"
        self.assertEqual(
            alpha_skeleton_sha256(spec),
            alpha_skeleton_sha256(impl),
        )

    def test_dual_evasion_uncalled_helper(self) -> None:
        spec = "def check(x, mv):\n    return x + mv == 4\n"
        impl = "def check(x, mv):\n    return x + mv == 4\n\ndef _pad():\n    return 0\n"
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_leading_unused_identity_helper_same_skeleton(self) -> None:
        spec = "def check(a, b):\n    total = a + b\n    return total == 4\n"
        impl = "def unused(z):\n    return z\n\ndef check(a, b):\n    total = a + b\n    return total == 4\n"
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_large_uncalled_helper_cannot_evade(self) -> None:
        spec = "def check(a, b):\n    total = a + b\n    return total == 4\n"
        impl = (
            "def bloated_uncalled(z, w, q, r):\n"
            "    s = z + w\n"
            "    t = s + q\n"
            "    u = t + r\n"
            "    v = u + z\n"
            "    w2 = v + w\n"
            "    return w2\n"
            "def check(a, b):\n"
            "    total = a + b\n"
            "    return total == 4\n"
        )
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    # --- Skeleton must distinguish kw-only and decorators ---

    def test_skeleton_distinguishes_kwonly_args(self) -> None:
        a = "def check(*, strict=True):\n    return 1\n"
        b = "def check():\n    return 1\n"
        self.assertNotEqual(alpha_skeleton_sha256(a), alpha_skeleton_sha256(b))

    def test_skeleton_distinguishes_decorators(self) -> None:
        a = "def check(x):\n    return x\n"
        b = "@cache\ndef check(x):\n    return x\n"
        self.assertNotEqual(alpha_skeleton_sha256(a), alpha_skeleton_sha256(b))

    # --- FLOAT_DIVISION: pathlib joins and line numbers ---

    def test_pathlib_div_not_flagged(self) -> None:
        src = (
            "from pathlib import Path\n"
            "ROOT = Path('x')\n"
            "p = ROOT / 'scripts'\n"
            "q = p / 'a' / 'b'\n"
        )
        rep = audit_checker_source(src, label="paths.py")
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)

    def test_float_division_reports_binop_line_not_zero(self) -> None:
        src = "def check(a, b):\n    return a / b\n"
        rep = audit_checker_source(src)
        divs = [f for f in rep["findings"] if f["rule"] == "FLOAT_DIVISION_IN_EXACT_CHECKER"]
        self.assertEqual(len(divs), 1)
        self.assertEqual(divs[0]["line"], 2)

    def test_test_module_path_join_pattern_is_clean(self) -> None:
        """This test file's ROOT / 'scripts' pattern must not be flagged."""
        snippet = "from pathlib import Path\nROOT = Path('.')\nx = ROOT / 'scripts'\n"
        rep = audit_checker_source(snippet)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)

    # --- F-01 fail-closed vs fail-open ---

    def test_f01_fail_closed_not_flagged(self) -> None:
        src = (
            "def verify(x):\n"
            "    ok = True\n"
            "    if not check_inner(x):\n"
            "        ok = False\n"
            "    return ok\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

    def test_f01_annassign_verified_true(self) -> None:
        src = (
            "def verify(x):\n"
            "    verified: bool = True\n"
            "    if x:\n"
            "        verified = True\n"
            "    return verified\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

    def test_f01_not_false_bypass(self) -> None:
        src = (
            "def verify():\n"
            "    verified = not False\n"
            "    if check():\n"
            "        verified = True\n"
            "    return verified\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

    def test_f01_certified_name(self) -> None:
        src = (
            "def verify():\n"
            "    certified = True\n"
            "    if gate():\n"
            "        certified = gate()\n"
            "    return certified\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

    def test_f01_guard_inside_for_loop(self) -> None:
        src = (
            "def verify(items):\n"
            "    ok = True\n"
            "    for it in items:\n"
            "        if not check(it):\n"
            "            ok = True\n"
            "    return ok\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

    # --- Missing rules from CR ---

    def test_vacuous_assert_and_return_true(self) -> None:
        src = "def check():\n    assert True\n    return True\n"
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("VACUOUS_ASSERT", rules)
        self.assertIn("VACUOUS_RETURN_TRUE", rules)

    def test_bare_assert_flagged(self) -> None:
        src = "def check(x):\n    assert x > 0\n"
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("BARE_ASSERT_STRIPPED_UNDER_O", rules)

    def test_except_exception_pass(self) -> None:
        src = "def check():\n    try:\n        run()\n    except Exception:\n        pass\n"
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("BARE_EXCEPT_SWALLOW", rules)

    def test_eval_flagged(self) -> None:
        src = "def check(s):\n    return bool(eval(s))\n"
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("EVAL_CALL", rules)

    def test_float_call_and_negative_exp_and_sqrt(self) -> None:
        src = (
            "import math\n"
            "def check():\n"
            "    x = float('1.5')\n"
            "    y = 2 ** -1\n"
            "    return math.sqrt(x) + y\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("FLOAT_CALL_IN_EXACT_CHECKER", rules)
        self.assertIn("FLOAT_NEGATIVE_EXPONENT", rules)
        self.assertIn("FLOAT_SQRT_IN_EXACT_CHECKER", rules)

    def test_strings_and_comments_do_not_trigger_hazards(self) -> None:
        src = (
            'def check():\n'
            '    """verified = True eval and except Exception"""\n'
            '    s = "ok = True; a / b; assert True"\n'
            "    return True is False\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)
        self.assertNotIn("EVAL_CALL", rules)
        self.assertNotIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)


if __name__ == "__main__":
    unittest.main()
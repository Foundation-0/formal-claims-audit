from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_python_checkers import (  # noqa: E402
    VERDICT_DISTINCT_LINT_CLEAN,
    VERDICT_FAIL,
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
        self.assertEqual(rep["verdict"], VERDICT_DISTINCT_LINT_CLEAN)
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
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
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
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_leading_unused_identity_helper_same_skeleton(self) -> None:
        spec = "def check(a, b):\n    total = a + b\n    return total == 4\n"
        impl = "def unused(z):\n    return z\n\ndef check(a, b):\n    total = a + b\n    return total == 4\n"
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
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
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
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

    def test_float_division_path_join_and_numeric_single_line(self) -> None:
        src = (
            "from pathlib import Path\n"
            "ROOT = Path(__file__).parent\n"
            'x = ROOT / "scripts"\n'
            "y = 3 / 2\n"
        )
        rep = audit_checker_source(src, label="paths.py")
        divs = [f for f in rep["findings"] if f["rule"] == "FLOAT_DIVISION_IN_EXACT_CHECKER"]
        self.assertEqual(len(divs), 1)
        self.assertEqual(divs[0]["line"], 4)

    def test_float_division_two_numeric_lines(self) -> None:
        src = "def check():\n    a = 1 / 2\n    b = 3 / 4\n"
        rep = audit_checker_source(src)
        divs = [f for f in rep["findings"] if f["rule"] == "FLOAT_DIVISION_IN_EXACT_CHECKER"]
        self.assertEqual(len(divs), 2)
        self.assertEqual({f["line"] for f in divs}, {2, 3})

    def test_test_module_path_join_pattern_is_clean(self) -> None:
        """This test file's ROOT / 'scripts' pattern must not be flagged."""
        snippet = "from pathlib import Path\nROOT = Path('.')\nx = ROOT / 'scripts'\n"
        rep = audit_checker_source(snippet)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)

    # --- F-01 fail-closed vs fail-open ---

    def test_f01_structural_all_good_without_suspicious_name(self) -> None:
        src = (
            "def run(items):\n"
            "    all_good = True\n"
            "    for i in items:\n"
            "        if i < 0:\n"
            '            print("bad")\n'
            "    return all_good\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)

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
        self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

    # --- Round 3 review controls ---

    def test_dual_called_identity_helper_same_skeleton(self) -> None:
        spec = "def check(s, d):\n    return s + d == 4\n"
        impl = (
            "def _t(m):\n"
            "    return m\n"
            "def check(s, d):\n"
            "    return _t(s) + _t(d) == 4\n"
        )
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_shared_local_module_import_fails(self) -> None:
        core = "def core(s, d):\n    return s + d == 4\n"
        spec_src = "from checker_core import core\n\ndef check(s, d):\n    return core(s, d)\n"
        impl_src = "import checker_core as cc\n\ndef check(s, d):\n    return cc.core(s, d)\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "checker_core.py").write_text(core, encoding="utf-8")
            (root / "spec.py").write_text(spec_src, encoding="utf-8")
            (root / "impl.py").write_text(impl_src, encoding="utf-8")
            rep = audit_dual_checkers(
                spec_src,
                impl_src,
                spec_path=root / "spec.py",
                impl_path=root / "impl.py",
            )
            self.assertEqual(rep["verdict"], VERDICT_FAIL)
            self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_dual_reordered_dead_assignments_same_skeleton(self) -> None:
        spec = "def check(a, b):\n    x = 1\n    y = 2\n    return a + b + x + y == 6\n"
        impl = "def check(a, b):\n    y = 2\n    x = 1\n    return a + b + x + y == 6\n"
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_math_log_and_exp_flagged(self) -> None:
        src = (
            "import math\n"
            "def check(a, b):\n"
            "    return math.log(a) + math.exp(b)\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

    def test_fraction_division_allowed_decimal_flagged(self) -> None:
        frac = (
            "from fractions import Fraction\n"
            "def check(a, b):\n"
            "    return Fraction(a) / Fraction(b)\n"
        )
        rep_frac = audit_checker_source(frac)
        self.assertNotIn(
            "FLOAT_DIVISION_IN_EXACT_CHECKER",
            {f["rule"] for f in rep_frac["findings"]},
        )
        dec = (
            "from decimal import Decimal\n"
            "def check(a, b):\n"
            "    return Decimal(a) / Decimal(b)\n"
        )
        rep_dec = audit_checker_source(dec)
        self.assertIn(
            "FLOAT_DIVISION_IN_EXACT_CHECKER",
            {f["rule"] for f in rep_dec["findings"]},
        )

    def test_purepath_and_path_join_variants_clean(self) -> None:
        src = (
            "from pathlib import Path, PurePath, PurePosixPath\n"
            "def check(name, x, y):\n"
            "    a = PurePath('a') / 'b'\n"
            "    b = PurePosixPath('x') / name\n"
            "    c = Path(x) / Path(y)\n"
            "    d = Path('root') / name\n"
            "    return len([a, b, c, d]) == 4\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertNotIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)

    def test_f01_try_except_pass_return_ok(self) -> None:
        src = (
            "def verify():\n"
            "    ok = True\n"
            "    try:\n"
            "        run_check()\n"
            "    except Exception:\n"
            "        pass\n"
            "    return ok\n"
        )
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("OPTIMISTIC_TRUE_DEFAULT_F01", rules)
        self.assertIn("BARE_EXCEPT_SWALLOW", rules)

    def test_int_int_true_division_explicit(self) -> None:
        clean = "def check(a: int, b: int):\n    return a // b\n"
        rep_ok = audit_checker_source(clean)
        self.assertNotIn(
            "FLOAT_DIVISION_IN_EXACT_CHECKER",
            {f["rule"] for f in rep_ok["findings"]},
        )
        bad = "def check(a: int, b: int):\n    return a / b\n"
        rep_bad = audit_checker_source(bad)
        divs = [f for f in rep_bad["findings"] if f["rule"] == "FLOAT_DIVISION_IN_EXACT_CHECKER"]
        self.assertEqual(len(divs), 1)

    def test_non_literal_exponent_flagged(self) -> None:
        src = "def check(x, e):\n    return x ** e\n"
        rep = audit_checker_source(src)
        rules = {f["rule"] for f in rep["findings"]}
        self.assertIn("FLOAT_NON_LITERAL_EXPONENT", rules)

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


class P16R3Round4Tests(unittest.TestCase):
    """Review controls from p16r3 probes (round 4)."""

    P16 = Path(__file__).resolve().parent / "fixtures" / "p16r3"

    def _read(self, name: str) -> str:
        return (self.P16 / name).read_text(encoding="utf-8")

    def _dual(self, left: str, right: str):
        spec_path = self.P16 / left
        impl_path = self.P16 / right
        return audit_dual_checkers(
            spec_path.read_text(encoding="utf-8"),
            impl_path.read_text(encoding="utf-8"),
            spec_path=spec_path,
            impl_path=impl_path,
        )

    def _single(self, name: str):
        path = self.P16 / name
        return audit_checker_source(path.read_text(encoding="utf-8"), label=str(path))

    def test_dual_noop_cosmetics_fail(self) -> None:
        for other in (
            "noop_two.py",
            "noop_lambda.py",
            "noop_deadcode.py",
            "noop_iftrue.py",
            "noop_mul1.py",
        ):
            with self.subTest(other=other):
                rep = self._dual("base.py", other)
                self.assertEqual(rep["verdict"], VERDICT_FAIL, other)
                self.assertFalse(rep["distinct_alpha_skeleton"], other)

    def test_dual_dynamic_import_fail(self) -> None:
        rep = self._dual("wrap_c.py", "wrap_d.py")
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        rules = {f["rule"] for f in rep["dual_findings"]}
        self.assertIn("DYNAMIC_IMPORT_IN_CHECKER", rules)

    def test_dual_shared_pkg_import_fail(self) -> None:
        rep = self._dual("wrap_e.py", "wrap_f.py")
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        self.assertFalse(rep["distinct_alpha_skeleton"])
        self.assertTrue(rep["shared_local_modules"])

    def test_dual_local_module_vs_inline_fail(self) -> None:
        rep = self._dual("wrap_a.py", "base.py")
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        rules = {f["rule"] for f in rep["dual_findings"]}
        self.assertIn("LOCAL_MODULE_DELEGATION_MISMATCH", rules)

    def test_math_import_alias_flagged(self) -> None:
        rules = {f["rule"] for f in self._single("m2.py")["findings"]}
        self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

    def test_cmath_and_statistics_flagged(self) -> None:
        for name in ("m4.py", "m5.py"):
            with self.subTest(name=name):
                rules = {f["rule"] for f in self._single(name)["findings"]}
                self.assertIn("FLOAT_MATH_CALL_IN_EXACT_CHECKER", rules)

    def test_pow_negative_exponent_flagged(self) -> None:
        rules = {f["rule"] for f in self._single("m8.py")["findings"]}
        self.assertIn("FLOAT_NEGATIVE_EXPONENT", rules)

    def test_fraction_alias_division_clean(self) -> None:
        self.assertTrue(self._single("f2.py")["clean"])

    def test_fraction_canonical_and_decimal(self) -> None:
        self.assertTrue(self._single("f1.py")["clean"])
        self.assertTrue(self._single("f3.py")["clean"])
        rules = {f["rule"] for f in self._single("f4.py")["findings"]}
        self.assertIn("FLOAT_DIVISION_IN_EXACT_CHECKER", rules)

    def test_math_int_ops_and_pathlib_regression(self) -> None:
        for name in ("m7.py", "fl.py", "p1.py"):
            with self.subTest(name=name):
                self.assertTrue(self._single(name)["clean"], name)

    def test_f01_shapes_regression(self) -> None:
        for name in ("e1.py", "e2.py", "e3.py", "e4.py"):
            with self.subTest(name=name):
                self.assertFalse(self._single(name)["clean"], name)
        self.assertTrue(self._single("e5.py")["clean"])

    def test_e6_optimistic_return_known_limit(self) -> None:
        """Documented limit: no F-01 without a guard after optimistic init."""
        self.assertTrue(self._single("e6.py")["clean"])


class P16R4Round5Tests(unittest.TestCase):
    P16 = Path(__file__).resolve().parent / "fixtures" / "p16r4"

    def _dual(self, left: str, right: str):
        spec_path = self.P16 / left
        impl_path = self.P16 / right
        return audit_dual_checkers(
            spec_path.read_text(encoding="utf-8"),
            impl_path.read_text(encoding="utf-8"),
            spec_path=spec_path,
            impl_path=impl_path,
        )

    def _single(self, name: str):
        path = self.P16 / name
        return audit_checker_source(path.read_text(encoding="utf-8"), label=str(path))

    def test_indep_positive_control_distinct(self) -> None:
        for other in ("indep.py", "indep2.py"):
            with self.subTest(other=other):
                rep = self._dual("base.py", other)
                self.assertEqual(rep["verdict"], VERDICT_DISTINCT_LINT_CLEAN)
                self.assertTrue(rep["distinct_alpha_skeleton"])

    def test_other_pair_positive_control_distinct(self) -> None:
        rep = self._dual("other1.py", "other2.py")
        self.assertEqual(rep["verdict"], VERDICT_DISTINCT_LINT_CLEAN)
        self.assertTrue(rep["distinct_alpha_skeleton"])

    def test_dual_cosmetic_evations_fail(self) -> None:
        for other in (
            "n_andtrue.py",
            "n_iife.py",
            "n_zeromul.py",
            "n_commute.py",
            "n_alias.py",
            "n_static.py",
            "n_default.py",
            "n_deco.py",
            "n_star.py",
            "n_walrus.py",
            "n_partial.py",
            "n_wrapsdeco.py",
            "n_bool.py",
            "n_ifret.py",
            "n_notne.py",
            "n_const.py",
            "n_sub.py",
        ):
            with self.subTest(other=other):
                rep = self._dual("base.py", other)
                self.assertEqual(rep["verdict"], VERDICT_FAIL, other)
                self.assertFalse(rep["distinct_alpha_skeleton"], other)

    def test_compare_direction_normalized(self) -> None:
        a = "def check(s, d):\n    return s + d < 5\n"
        b = "def check(s, d):\n    return 5 > s + d\n"
        self.assertEqual(alpha_skeleton_sha256(a), alpha_skeleton_sha256(b))

    def test_different_predicate_still_limit(self) -> None:
        """Inequality vs equality (e.g. ``4 > s+d`` vs ``s+d==4``) is not unified (documented limit)."""
        rep = self._dual("base.py", "n_gt_limit.py")
        self.assertEqual(rep["verdict"], VERDICT_DISTINCT_LINT_CLEAN)
        self.assertTrue(rep["distinct_alpha_skeleton"])

    def test_relative_import_shared_module_not_delegation_mismatch(self) -> None:
        core = "def core(s, d):\n    return s + d == 4\n"
        spec_src = "from .pkg import mod\n\ndef check(s, d):\n    return mod.core(s, d)\n"
        impl_src = "from .pkg.mod import core\n\ndef check(s, d):\n    return core(s, d)\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "wrap_pkg"
            root.mkdir(parents=True)
            (root / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg" / "mod.py").write_text(core, encoding="utf-8")
            (root / "spec.py").write_text(spec_src, encoding="utf-8")
            (root / "impl.py").write_text(impl_src, encoding="utf-8")
            rep = audit_dual_checkers(
                spec_src,
                impl_src,
                spec_path=root / "spec.py",
                impl_path=root / "impl.py",
            )
            self.assertEqual(rep["verdict"], VERDICT_FAIL)
            self.assertTrue(rep["shared_local_modules"])
            rules = {f["rule"] for f in rep.get("dual_findings", [])}
            self.assertNotIn("LOCAL_MODULE_DELEGATION_MISMATCH", rules)

    def test_single_float_hazards_round5(self) -> None:
        flagged = (
            "s_truediv.py",
            "s_optruediv.py",
            "s_getattr.py",
            "s_dunder.py",
            "s_half.py",
        )
        for name in flagged:
            with self.subTest(name=name):
                self.assertFalse(self._single(name)["clean"], name)

    def test_fraction_local_and_module_alias_clean(self) -> None:
        self.assertTrue(self._single("fp_localalias.py")["clean"])
        self.assertTrue(self._single("fp_modalias.py")["clean"])

    def test_syntax_error_json_fail(self) -> None:
        rep = audit_checker_source("def check(\n", label="broken.py")
        self.assertFalse(rep["clean"])
        self.assertEqual(rep["verdict"], VERDICT_FAIL)
        self.assertIn("SYNTAX_ERROR", {f["rule"] for f in rep["findings"]})
        self.assertGreaterEqual(rep["findings"][0]["line"], 1)


if __name__ == "__main__":
    unittest.main()
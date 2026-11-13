from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_python_checkers import audit_checker_source, audit_dual_checkers, alpha_skeleton_sha256


class AuditPythonCheckersTests(unittest.TestCase):
    def test_rejects_alpha_renamed_copy_paste_checkers(self) -> None:
        spec = "def check(state, step):\n    return state + step == 4\n"
        alpha_copy = "def verify(x, mv):\n    return x + mv == 4\n"
        rep = audit_dual_checkers(spec, alpha_copy)
        self.assertEqual(rep["verdict"], "DETECTED")
        self.assertFalse(rep["distinct_alpha_skeleton"])

    def test_distinct_syntax_reports_only_not_detected(self) -> None:
        spec = "def check(items):\n    return len(frozenset(items)) == 3\n"
        impl = (
            "def check_mask(items):\n"
            "    mask = 0\n"
            "    for v in items:\n"
            "        mask |= (1 << v)\n"
            "    return bin(mask).count('1') == 3\n"
        )
        rep = audit_dual_checkers(spec, impl)
        self.assertEqual(rep["verdict"], "NOT_DETECTED")
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
        self.assertIn("UNTYPED_TRUE_DIVISION", rules)

    def test_separate_function_scopes_allow_independent_local_renames(self):
        first = "def positive(x): return x > 0\ndef verify(x): return positive(x)\n"
        second = "def positive(a): return a > 0\ndef verify(b): return positive(b)\n"
        self.assertEqual(alpha_skeleton_sha256(first), alpha_skeleton_sha256(second))
        self.assertEqual(audit_dual_checkers(first, second)["comparison_status"], "MATCH")

    def test_resolves_shadowed_local_and_module_binding(self):
        first = "def helper(x): return x\ndef verify(helper): return helper(2)\n"
        renamed = "def other(a): return a\ndef check(local): return local(2)\n"
        global_call = "def other(a): return a\ndef check(local): return other(2)\n"
        self.assertEqual(alpha_skeleton_sha256(first), alpha_skeleton_sha256(renamed))
        self.assertNotEqual(alpha_skeleton_sha256(first), alpha_skeleton_sha256(global_call))

    def test_unsupported_binding_constructs_are_inconclusive(self):
        cases = [
            "def check(*args): return True\n",
            "def check(x=1): return x\n",
            "@decorator\ndef check(x): return x\n",
            "def check(x):\n def nested(y): return y\n return nested(x)\n",
            "def check(xs): return [x for x in xs]\n",
            "def check(x): return helper(value=x)\n",
            "class Check: pass\n",
        ]
        for source in cases:
            with self.subTest(source=source):
                report = audit_dual_checkers(source, source)
                self.assertEqual(report["verdict"], "INCONCLUSIVE")
                self.assertIsNone(report["distinct_alpha_skeleton"])

    def test_fraction_division_is_untyped_review_finding_with_line(self):
        source = "from fractions import Fraction\ndef check():\n return Fraction(1, 3) / Fraction(2, 3)\n"
        report = audit_checker_source(source)
        self.assertEqual(report["findings_count"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule"], "UNTYPED_TRUE_DIVISION")
        self.assertEqual(finding["line"], 3)
        self.assertIn("stays exact", finding["detail"])

    def test_augmented_true_division_is_reported_at_expression_line(self):
        source = "def check(n):\n n /= 2\n return n == 0\n"
        report = audit_checker_source(source)
        self.assertEqual(report["status"], "DETECTED")
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["rule"], "UNTYPED_TRUE_DIVISION")
        self.assertEqual(report["findings"][0]["line"], 2)

    def test_local_annotations_are_unsupported_for_comparison(self):
        source = "def check(n):\n x: int = n\n return x\n"
        report = audit_dual_checkers(source, source)
        self.assertEqual(report["verdict"], "INCONCLUSIVE")
        self.assertEqual(report["comparison_status"], "INCONCLUSIVE")
        self.assertIsNone(report["distinct_alpha_skeleton"])
        self.assertIn("AnnAssign", report["comparison_limit"])

    def test_noop_difference_does_not_certify_independence(self):
        first = "def verify(candidate, n):\n assert True\n return True\n"
        second = "def verify(candidate, n):\n pass\n return True\n"
        report = audit_dual_checkers(first, second)
        self.assertEqual(report["verdict"], "NOT_DETECTED")
        self.assertIn("no certification", report["meaning"])
        # Both violate candidate**2 == n for (2, 3); the scanner cannot infer that contract.
        for source in (first, second):
            namespace = {}
            exec(source, namespace)
            self.assertTrue(namespace["verify"](2, 3))
        self.assertNotEqual(2**2, 3)

    def test_parse_error_is_inconclusive(self):
        source = "def check(:\n"
        self.assertEqual(audit_checker_source(source)["status"], "INCONCLUSIVE")
        self.assertEqual(audit_dual_checkers(source, source)["verdict"], "INCONCLUSIVE")

    def test_cli_status_codes_and_json(self):
        import json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a.py", Path(tmp) / "b.py"
            a.write_text("def check(x): return x > 0\n")
            b.write_text("def check(y): return y > 0\n")
            command = [sys.executable, str(ROOT / "scripts/audit_python_checkers.py"), str(a)]
            single = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(single.returncode, 0)
            self.assertEqual(json.loads(single.stdout)["status"], "NOT_DETECTED")
            dual = subprocess.run(command + ["--independent", str(b)], capture_output=True, text=True)
            self.assertEqual(dual.returncode, 1)
            self.assertEqual(json.loads(dual.stdout)["verdict"], "DETECTED")
            b.write_text("def check(*args): return True\n")
            unsupported = subprocess.run(command + ["--independent", str(b)], capture_output=True, text=True)
            self.assertEqual(unsupported.returncode, 2)
            self.assertEqual(json.loads(unsupported.stdout)["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()

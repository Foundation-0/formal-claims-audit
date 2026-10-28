"""Exercise the public CLI with fictional verdicts, never real proof projects."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_verdicts.py"
FIXTURE = Path(__file__).parent / "fixtures" / "example-lab-theorem-1.json"
EXAMPLE = json.loads(FIXTURE.read_text(encoding="utf-8"))


class VerdictCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / FIXTURE.name

    def write(self, value):
        self.path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def run_checker(self, directory=None, *, script=SCRIPT, cwd=None):
        arguments = [sys.executable, str(script)]
        if directory is not None:
            arguments.append(str(directory))
        return subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, check=False)

    def check(self, value, *, invalid_field=None):
        self.write(value)
        result = self.run_checker(self.directory)
        if invalid_field is None:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(self.path.name, result.stderr)
            self.assertIn(invalid_field, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def test_documented_example(self):
        self.check(EXAMPLE)

    def test_all_five_verdicts(self):
        for verdict in ("faithful", "weaker", "stronger", "different", "does not build"):
            with self.subTest(verdict=verdict):
                self.check(dict(EXAMPLE, verdict=verdict))

    def test_every_top_level_field_is_required(self):
        for field in EXAMPLE:
            with self.subTest(field=field):
                value = copy.deepcopy(EXAMPLE)
                del value[field]
                self.check(value, invalid_field=field)

    def test_every_nested_field_is_required(self):
        for parent in ("lab_statement", "independent_statement", "tool"):
            for field in EXAMPLE[parent]:
                with self.subTest(parent=parent, field=field):
                    value = copy.deepcopy(EXAMPLE)
                    del value[parent][field]
                    result = self.check(value, invalid_field=field)
                    self.assertIn(parent, result.stderr)

    def test_id_must_match_filename(self):
        for identifier in ("other", None, 1, True, [], {}):
            with self.subTest(identifier=identifier):
                self.check(dict(EXAMPLE, id=identifier), invalid_field="id")

    def test_commit_must_be_full_hex_hash(self):
        for commit in (None, 1, "", "a" * 39, "a" * 41, "g" * 40, "a" * 40 + "\n"):
            with self.subTest(commit=commit):
                self.check(dict(EXAMPLE, source_commit=commit), invalid_field="source_commit")
        self.check(dict(EXAMPLE, source_commit="ABCDEF0123" * 4))

    def test_verdict_must_be_one_of_documented_values(self):
        for verdict in (None, 1, True, [], {}, "Faithful", "does-not-build", "unknown"):
            with self.subTest(verdict=verdict):
                self.check(dict(EXAMPLE, verdict=verdict), invalid_field="verdict")

    def test_nullable_fields_accept_missing_yet_values(self):
        value = {field: None for field in EXAMPLE}
        for field in ("id", "source_commit", "verdict"):
            value[field] = EXAMPLE[field]
        self.check(value)

    def test_nested_values_may_be_null(self):
        value = copy.deepcopy(EXAMPLE)
        for parent in ("lab_statement", "independent_statement", "tool"):
            value[parent] = dict.fromkeys(value[parent])
        self.check(value)

    def test_text_fields_reject_non_strings(self):
        fields = ("source_repo", "claim", "claim_link", "command", "output_summary", "reviewer")
        for field in fields:
            with self.subTest(field=field):
                self.check(dict(EXAMPLE, **{field: 42}), invalid_field=field)

    def test_nested_fields_reject_non_objects_and_non_strings(self):
        for parent in ("lab_statement", "independent_statement", "tool"):
            for wrong_type in ("text", [], 42, True):
                with self.subTest(parent=parent, wrong_type=wrong_type):
                    self.check(dict(EXAMPLE, **{parent: wrong_type}), invalid_field=parent)
            for field in EXAMPLE[parent]:
                with self.subTest(parent=parent, field=field):
                    value = copy.deepcopy(EXAMPLE)
                    value[parent][field] = False
                    self.check(value, invalid_field=field)

    def test_axioms_must_be_array_of_strings_or_null(self):
        for axioms in ("propext", {}, True, [None], [1], ["propext", {}]):
            with self.subTest(axioms=axioms):
                self.check(dict(EXAMPLE, axioms=axioms), invalid_field="axioms")
        self.check(dict(EXAMPLE, axioms=[]))

    def test_extra_fields_are_allowed(self):
        value = copy.deepcopy(EXAMPLE)
        value["notes"] = "Fictional fixture only; not a research verdict."
        value["tool"]["documentation"] = "https://example.org/tool"
        self.check(value)

    def test_top_level_must_be_object(self):
        for value in (None, [], "text", 1, True):
            with self.subTest(value=value):
                self.check(value, invalid_field="object")

    def test_malformed_json_is_reported_without_traceback(self):
        self.path.write_text('{"id":', encoding="utf-8")
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn(self.path.name, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_duplicate_keys_are_rejected_at_any_depth(self):
        for text in (
            json.dumps(EXAMPLE)[:-1] + ', "verdict": "weaker"}',
            json.dumps(EXAMPLE).replace('"name": "comparator"', '"name": "one", "name": "two"'),
        ):
            with self.subTest(text=text):
                self.path.write_text(text, encoding="utf-8")
                result = self.run_checker(self.directory)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("duplicate", result.stderr.lower())

    def test_nonstandard_json_numbers_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                self.path.write_text(json.dumps(EXAMPLE)[:-1] + ', "extra": ' + constant + '}', encoding="utf-8")
                result = self.run_checker(self.directory)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(self.path.name, result.stderr)

    def test_invalid_utf8_is_reported_without_traceback(self):
        self.path.write_bytes(b'\xff')
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn(self.path.name, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_all_files_are_checked_and_reported(self):
        self.write(EXAMPLE)
        for name in ("b-broken", "a-broken"):
            (self.directory / (name + ".json")).write_text("{}", encoding="utf-8")
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn("a-broken.json", result.stderr)
        self.assertIn("b-broken.json", result.stderr)
        self.assertLess(result.stderr.index("a-broken.json"), result.stderr.index("b-broken.json"))

    def test_empty_directory_is_explicit_and_non_json_files_are_ignored(self):
        (self.directory / "README.md").write_text("Not JSON.", encoding="utf-8")
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\b0\b")

    def test_bare_json_filename_is_checked_and_has_no_valid_id(self):
        self.path = self.directory / ".json"
        self.path.write_text("not JSON", encoding="utf-8")
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(".json", result.stderr)
        for identifier in ("", ".json"):
            with self.subTest(identifier=identifier):
                self.check(dict(EXAMPLE, id=identifier), invalid_field="id")

    def test_missing_or_non_directory_paths_fail(self):
        self.write(EXAMPLE)
        for path in (self.directory / "missing", self.path):
            with self.subTest(path=path):
                result = self.run_checker(path)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_directory_named_json_is_a_read_error(self):
        self.path.mkdir()
        result = self.run_checker(self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn(self.path.name, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_default_directory_is_relative_to_script_not_working_directory(self):
        project = self.directory / "project"
        (project / "scripts").mkdir(parents=True)
        (project / "verdicts").mkdir()
        script = project / "scripts" / SCRIPT.name
        shutil.copyfile(SCRIPT, script)
        shutil.copyfile(FIXTURE, project / "verdicts" / FIXTURE.name)
        (self.directory / "verdicts").mkdir()
        (self.directory / "verdicts" / "broken.json").write_text("{}", encoding="utf-8")
        result = self.run_checker(script=script, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\b1\b")


if __name__ == "__main__":
    unittest.main()

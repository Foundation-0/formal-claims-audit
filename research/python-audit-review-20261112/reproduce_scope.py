#!/usr/bin/env python3
"""Bounded scope probes for PR16. Does not edit or import the broken source file.

The exact original bytes before the broken __main__ guard are loaded in memory.
Results describe those definitions, not a runnable submitted CLI.
"""
from pathlib import Path
from fractions import Fraction
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "repo/scripts/audit_python_checkers.py"
EXPECTED_SHA256 = "e3ce760e8f3a1fddf0d17fe2f8249708431eb7513c6085f2b9cfb9af09521ade"
raw = SOURCE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED_SHA256
text = raw.decode()
marker = 'if ____name__ == "__main__":'
assert text.count(marker) == 1
definitions, _ = text.split(marker)
module = {"__name__": "pinned_review_definitions"}
exec(compile(definitions, str(SOURCE) + ":lines1-180", "exec"), module)
single = module["audit_checker_source"]
dual = module["audit_dual_checkers"]

def evaluate(source, name, *args):
    namespace = {}
    exec(source, namespace)
    return namespace[name](*args)

# Positive controls establish the functions were loaded and rules really ran.
alpha_a = "def check(state, step):\n    return state + step == 4\n"
alpha_b = "def verify(x, mv):\n    return x + mv == 4\n"
hazards = (
    "def verify(py_ok, other):\n"
    "    differential_match = True\n"
    "    if other is not None:\n"
    "        differential_match = other == py_ok\n"
    "    tolerance = 0.001 / 2\n"
    "    return py_ok and differential_match\n"
)

# Contract: verify(n, candidate) should accept only candidate**2 == n.
stub_a = "def verify(n, candidate):\n    assert True\n    return True\n"
stub_b = "def verify(n, candidate):\n    pass\n    assert True\n    return True\n"

# A copied substantive checker also passes when a no-op is added.
noop_b = "def verify(x, mv):\n    pass\n    return x + mv == 4\n"

# Pure local renaming in separate scopes changes the single global name map.
scoped_a = "def positive(x):\n    return x > 0\ndef verify(x):\n    return positive(x)\n"
scoped_b = "def positive(a):\n    return a > 0\ndef verify(b):\n    return positive(b)\n"

# Exact rational division is rejected by a rule which states '/' creates floats.
rational = (
    "from fractions import Fraction\n"
    "def verify():\n"
    "    return Fraction(1, 3) / Fraction(2, 3) == Fraction(1, 2)\n"
)

# The literal rule does not detect constructed floats, even in a comparison.
constructed_float = (
    "def verify():\n"
    "    return float('0.1') + float('0.2') == float('0.3')\n"
)

# The same fail-open behavior can use an ordinary name outside the hardcoded set.
renamed_fallback = hazards.replace("differential_match", "secondary_ok").replace(
    "    tolerance = 0.001 / 2\n", ""
)

results = {
    "source_sha256": EXPECTED_SHA256,
    "execution_scope": "Unchanged source lines 1-180 loaded in memory; broken CLI tail excluded",
    "positive_alpha_copy": dual(alpha_a, alpha_b),
    "positive_known_hazards": single(hazards),
    "vacuous_stubs": {
        "contract": "candidate squared equals n",
        "invalid_input": [2, 3],
        "expected_acceptance": False,
        "acceptance": [evaluate(stub_a, "verify", 2, 3), evaluate(stub_b, "verify", 2, 3)],
        "audit": dual(stub_a, stub_b),
    },
    "copy_with_pass": dual(alpha_a, noop_b),
    "copy_with_scope_local_renaming": {
        "inputs": [-1, 0, 1],
        "outputs_a": [evaluate(scoped_a, "verify", n) for n in [-1, 0, 1]],
        "outputs_b": [evaluate(scoped_b, "verify", n) for n in [-1, 0, 1]],
        "audit": dual(scoped_a, scoped_b),
    },
    "exact_fraction_division": {"result": evaluate(rational, "verify"), "audit": single(rational)},
    "constructed_floats": {"result": evaluate(constructed_float, "verify"), "audit": single(constructed_float)},
    "renamed_fail_open": {"accepts_without_secondary": evaluate(renamed_fallback, "verify", True, None), "audit": single(renamed_fallback)},
    "missing_goal_boundary_control": {
        "states": ["start", "goal"],
        "edges": [["start", "goal", 1]],
        "potential": {"start": 35, "goal": 35},
        "local_edge_inequality_holds": 35 <= 1 + 35,
        "actual_shortest_goal_distance": 1,
        "asserted_lower_bound_if_goal_boundary_omitted": 35,
        "required_additional_boundary": "h(goal) <= 0",
    },
}
assert results["positive_alpha_copy"]["verdict"] == "FAIL"
assert len(results["positive_known_hazards"]["findings"]) == 3
assert results["vacuous_stubs"]["audit"]["verdict"] == "PASS"
assert results["vacuous_stubs"]["acceptance"] == [True, True]
assert results["copy_with_pass"]["verdict"] == "PASS"
assert results["copy_with_scope_local_renaming"]["audit"]["verdict"] == "PASS"
assert results["exact_fraction_division"]["result"] is True
assert not results["exact_fraction_division"]["audit"]["clean"]
assert results["constructed_floats"]["audit"]["clean"]
assert results["renamed_fail_open"]["audit"]["clean"]
print(json.dumps(results, indent=2))

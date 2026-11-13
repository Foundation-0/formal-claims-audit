The Python checker auditor is useful as a static warning tool after repair. The submitted commit cannot run, and its `PASS` result does not establish checker independence or certificate soundness. Four concrete defects or mismatches are reproduced below. No repository files were changed and no review was posted.

The reviewed change is [formal-claims-audit PR 16](https://github.com/Foundation-0/formal-claims-audit/pull/16), head `467a580956824e76c193f8ae72d83f0a330ecd3d`, base `bacf05953c10bf5105fa1209a127392d395e2f92`. Source hashes and the local Python 3.14.6 environment are recorded in [source-manifest.json](source-manifest.json).

| Finding | Source | Reproduced effect |
|---|---|---|
| The script and its new tests do not parse | Script lines 181–183, test line 48 | CLI exits 1 with `IndentationError`. Test discovery passes 24 existing tests but fails to import the added module with `SyntaxError`. None of the three new tests runs. |
| Local renaming can evade the copy check | Script lines 42–49, 62–76 | Renaming arguments in separate function scopes produces different hashes and dual `PASS` for a copied program. |
| Advertised stub detection is absent | Script lines 86–129 | `assert True; return True` is clean. Adding only `pass` to a second copy produces dual `PASS`. Both accept a false square certificate. |
| Exact rational division is classified as floating point | Script lines 94–99 | `Fraction(1, 3) / Fraction(2, 3)` is exact but raises the float-division finding, with reported line 0. |

The [script](https://github.com/Foundation-0/formal-claims-audit/blob/467a580956824e76c193f8ae72d83f0a330ecd3d/scripts/audit_python_checkers.py) ends with a misspelled `____name__` guard and two differently indented `raise` statements. The [test file](https://github.com/Foundation-0/formal-claims-audit/blob/467a580956824e76c193f8ae72d83f0a330ecd3d/tests/test_audit_python_checkers.py) ends with `if_ __name__`.

The advertised `--single`, `--dual`, and `--json` options are also absent: the parser defines a positional file, `--independent`, and `--allow-floats`.

The name normalizer keeps one map for the entire source. These programs differ only in locally bound argument names, yet receive distinct hashes and `PASS`:

```python
def positive(x):
    return x > 0
def verify(x):
    return positive(x)
```

```python
def positive(a):
    return a > 0
def verify(b):
    return positive(b)
```

The stub control uses the explicit contract `candidate**2 == n`. Both functions accept `(n=2, candidate=3)`, although `9 != 2`. The second function adds only a no-op `pass` statement. The auditor reports clean individual checks and dual `PASS`.

A copied substantive checker with one added `pass` also passes. This settles the limit of AST inequality without assuming an adversarial code author.

The division rule inspects an operator node without its operands. Python allows division to use type-specific behavior, and `Fraction` supports rational arithmetic. The exact division above equals `Fraction(1, 2)`. Changing `/` to `//`, as suggested by the finding, would change this result to zero.

The [Python arithmetic reference](https://docs.python.org/3/reference/expressions.html#binary-arithmetic-operations) and [Fraction documentation](https://docs.python.org/3/library/fractions.html) describe these operations.

[reproduce_scope.py](reproduce_scope.py) loads the unchanged first 180 source lines in memory, after checking their file hash. It excludes the broken entry-point tail. This separation permits assessment of the defined functions and does not count as a successful run of the submitted program.

[scope-results.json](scope-results.json) contains every result. The literal-copy and named fallback controls do trigger their expected findings.

```sh
cd repo
python3 -m unittest discover -s tests -v
python3 scripts/audit_python_checkers.py --help
python3 scripts/check_verdicts.py
cd ../output
python3 reproduce_scope.py
```

The existing verdict-format checker exits 0 with zero verdict files. That result concerns its existing JSON format checks. [baseline-1.txt](baseline-1.txt), [baseline-2.txt](baseline-2.txt), and [baseline-3.txt](baseline-3.txt) preserve the command outputs.

The supported conclusion from a clean audit is: “none of these syntax patterns was found.” The tool checks float and complex literals, `/`, `global` and `nonlocal`, bare exception handlers, and a narrow assignment pattern for selected flag names. Constructed floats and the same missing-secondary-checker fallback under the name `secondary_ok` pass the recorded controls. No certificate or domain specification is evaluated.

For paired checking, distinct syntax can be useful evidence about copying. Evidence of independent reasoning also needs separate derivations, representations, implementations, and tests aimed at shared mistakes. Two implementations can reproduce the same incorrect model. Mutation tests measure the mutations supplied to them. Their success does not establish coverage of every possible defect.

The related [f0 scouting note](https://github.com/Foundation-0/f0/blob/f6d42123287b58e98801e6e5d77b384fcb0099ac/deep-fields/scouting/combinatorial-planning-verified-bar.md) and [math0 area proposal](https://github.com/Foundation-0/math0/blob/3d3198246c4f2ee1fc1079c57cdd936c4f2b34d0/AREAS.md) need one further proof condition: a lower-bound potential requires a goal boundary as well as edge inequalities.

For a one-edge graph `start -> goal` of cost 1, the constant potential `h = 35` satisfies `h(s) <= 1 + h(s')` on every edge, but the shortest path costs 1. Along any path, the inequalities give `h(start) <= path_cost + h(goal)`. A condition such as `h(goal) <= 0`, plus coverage of the actual transitions and relevant goals, turns this into a lower bound. The probe records this counterexample.

This omission in the stated checking requirement does not show that a reported Sokoban result is false. This review did not replay the room records or inspect their underlying search certificates. The connected research opportunity is to attach the full proof obligations to each certificate: the model, accepted witness, covered transitions, boundary conditions, and source hashes.

The recommendation is to hold this commit. Reconsider it when the unmodified CLI and tests run, the copy detector handles the declared binding scopes, stub claims match implemented checks, and exact-division warnings accurately describe what was detected.

The report should label syntax screening separately from certificate acceptance and independent verification. Further broad mutation searches are unnecessary for these conclusions.

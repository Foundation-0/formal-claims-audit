# Review and repair of the Python checker scanner

The [original review](REVIEW.md) is frozen against the submitted change at `467a580956824e76c193f8ae72d83f0a330ecd3d`. Its recommendation concerns that revision. The repair changes the tool into a runnable, explicitly limited source-pattern scanner. It does not certify checker independence or mathematical soundness.

The source snapshot is stored as text because its original CLI tail does not parse. The unchanged scope probe loads only the definitions before that tail. The wrapper reconstructs its temporary directory layout and compares the JSON result with the saved original output.

```sh
python3 research/python-audit-review-20261112/replay_original.py
python3 -m unittest discover -s tests -v
```

The first command verifies that the documented original counterexamples reproduce. The second tests the repaired implementation. They answer different questions. The original review's checkout commands describe the initial review layout. Failure-log checkout paths are redacted in this public copy.

[Repair validation](repair-validation.json) binds the initial repaired files and records the implementation checks. A separate scientific review is supplied alongside it. Unsupported syntax now returns an inconclusive comparison, and different supported syntax supplies no independence guarantee.

The goal-boundary example also applies to the connected planning proposal: edge inequalities alone establish a potential difference, not an absolute lower bound. A complete certificate needs the goal boundary and coverage of its intended state graph. This observation does not refute an underlying Sokoban result.

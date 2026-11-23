# Five-family audit replay

The inventory records existing source paths, not an assessment of mathematical correctness. Each record's `line_start_tokens` field is produced by `scripts/extract_line_start_tokens.py` under the rule in [RULE.md](RULE.md); it is not a Lean parser, so names must be confirmed in Lean before `#print axioms`.

For each record, an independent reader first derives the intended statement from the paper, without reading the comparator. A separate worker then builds the pinned source in a sandbox with no credentials, records the exact Lean toolchain, and runs #print axioms on the selected declarations. The comparison must name both pinned statements and its bridge lemma or comparator output.

No non-faithful verdict is reported outside this repository before qualified human review. Missing build results remain null, rather than being classified as a build failure.

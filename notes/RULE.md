# Line-start token extraction

The field `line_start_tokens` in `family-source-inventory.json` is produced only by
`scripts/extract_line_start_tokens.py`. It is not a Lean parser and must not be read as a
complete theorem or declaration list.

## What counts

On each line, after optional leading whitespace:

1. Optional modifiers (any order, repeated): `private`, `protected`, `unsafe`, `noncomputable`.
2. A declaration keyword: `theorem`, `lemma`, `def`, or `abbrev` (not `structure`, `inductive`,
   `class`, or `instance`).
3. The first identifier token on that line, which may be namespace-qualified (`Gate.eval`).

Every matching line counts, including `noncomputable def` and `noncomputable abbrev`.

## Files

All `.lean` files listed in `family-source-inventory.json` at the pinned commit
`source_commit`. Local copies for offline checks live under `notes/pinned-sources/` with the
same relative paths as in each record's `path` field.

## Namespaces

No namespace tracking is performed. Qualified names come only from dot-separated identifiers on
the declaration line (`Program.eval`, `Circuit.Computes`).

## Output

Tokens are collected in source order, then deduplicated (first occurrence kept). The inventory
stores the resulting list per record.
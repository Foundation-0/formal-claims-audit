# Verdict files

Each audited claim gets one JSON file in this folder, named `<id>.json`. A verdict compares two things: the formal
(Lean) statement the lab proved, and an independent formal statement of what the paper claims in words.

## Verdicts

| verdict | meaning |
|---|---|
| `faithful` | the lab's formal statement says what the paper claims |
| `weaker` | the lab's formal statement proves less than the paper claims |
| `stronger` | the lab's formal statement proves more than the paper claims |
| `different` | the two statements are about different things, or neither implies the other |
| `does not build` | the lab's Lean project does not build at the pinned commit, so nothing was compared |

Write a finding as "the formal statement differs from the paper's claim", never "the proof is wrong". A person who
knows the field reviews every verdict other than `faithful` before it is reported anywhere.

## Fields

All fields are required. Use `null` for a value that does not exist yet, such as `reviewer` before the review.

The checker requires `id`, `source_commit` and `verdict` to have the concrete values described below.
Other text values may be strings or `null`. Each statement or tool may be `null` when unavailable;
when it is an object, all its listed fields must be present, with string or `null` values.
`axioms` is an array of strings (possibly empty), or `null` when not yet recorded. Additional fields are
allowed. A missing field is not the same as an explicit `null`.
Files must be UTF-8 JSON with no duplicate keys or non-JSON constants such as `NaN`.
Run `python3 scripts/check_verdicts.py` from the repository root to check this format; it does not
establish that a verdict is correct or ready to publish.

| field | what it holds |
|---|---|
| `id` | a short name, the same as the file name without `.json` |
| `source_repo` | the URL of the repository that holds the lab's Lean files |
| `source_commit` | the full 40-character hexadecimal commit hash that was audited |
| `claim` | the claim in words, quoted from the paper |
| `claim_link` | a link to the paper, at the page or section of the claim |
| `lab_statement` | the lab's formal statement: `file` (path in the source repository), `name` (the theorem's name) and `lean` (its text, copied exactly) |
| `independent_statement` | the independent formal statement: `lean` (its text), `source` (formal-conjectures with a link at a commit, or "written for this audit") and `author` (who wrote it) |
| `tool` | `name` and `version` of the tool used for the comparison, and `lean_version` |
| `command` | the exact command that was run |
| `output_summary` | what the command printed, shortened to the lines that matter |
| `axioms` | the axioms the lab's proof uses, as printed by `#print axioms` |
| `verdict` | one of the five verdicts above |
| `reviewer` | the GitHub username of the person who reviewed the verdict, or `null` until then |

Record who wrote the independent statement, because it can be wrong too. Erdős #124's formal statement once had a
typo.

## Example

The values below show the shape only. They are not a real verdict.

```json
{
  "id": "example-lab-theorem-1",
  "source_repo": "https://github.com/example/lab-proofs",
  "source_commit": "0123456789abcdef0123456789abcdef01234567",
  "claim": "For every natural number n, the sum of the first n odd numbers is n squared.",
  "claim_link": "https://example.org/paper.pdf#page=3",
  "lab_statement": {
    "file": "Proofs/OddSum.lean",
    "name": "odd_sum",
    "lean": "theorem odd_sum (n : ℕ) : ∑ i ∈ Finset.range n, (2 * i + 1) = n ^ 2"
  },
  "independent_statement": {
    "lean": "theorem odd_sum' : ∀ n : ℕ, ∑ i ∈ Finset.range n, (2 * i + 1) = n ^ 2",
    "source": "written for this audit",
    "author": "example-user"
  },
  "tool": {"name": "comparator", "version": "<version>", "lean_version": "<version>"},
  "command": "<the exact command>",
  "output_summary": "<the lines of output that matter>",
  "axioms": ["propext", "Classical.choice", "Quot.sound"],
  "verdict": "faithful",
  "reviewer": null
}
```

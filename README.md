# formal-claims-audit

**When an AI-claimed result is called "Lean-verified" or "formally verified", does its formal statement say what
the paper claims?**

A proof checker such as Lean confirms that a proof proves its formal statement: the theorem written out precisely in
the checker's own language. It does not confirm that the formal statement says what the paper claims in words. If
the formal statement is weaker than the paper's claim, or about something slightly different, the proof still checks
and the paper's claim is still unproved. This project checks that second step, in public, so that a "formally
verified" label means what it says.

Part of Foundation0's mathematics work ([math0](https://github.com/Foundation-0/math0)). It also serves Foundation0's
[Ledger](https://github.com/Foundation-0/f0/blob/main/docs/data/ledger.json), the record of what AI has helped
discover and how far each claim has been checked. The project began in Foundation0's
[deep-fields scouting](https://github.com/Foundation-0/f0/tree/main/deep-fields) of 18–19 October 2026.

**Status: not started. No verdicts yet.**

| Claim | Source and commit | Verdict | Status |
|---|---|---|---|
| none yet | | | |

A verdict says whether the formal statement is faithful to the paper's claim, weaker, stronger, different, or does
not build. The format of a verdict file is in [verdicts/README.md](verdicts/README.md).

## What is known

Checked against their sources on 19 Oct 2026:

- OpenAI announced [openai/math](https://github.com/openai/math) on 6 Oct 2026, with 722 manuscripts grouped into
  372 result families
  ([launch post](https://community.openai.com/t/first-look-at-mathematics-manuscripts-from-an-internal-frontier-model-at-openai/1403886)).
  Three were withdrawn on 7 Oct (see history.md in that repository), leaving 719. Its README says "~42% top-line
  results formalized", which is 300 of 719. That is OpenAI's own count.
- Bastounis, Circelli and Hansen describe a Lean proof that does not match the proof in words: "the formalised Lean
  proof does not correspond to the NL proof of blow-up of solutions to the Navier-Stokes equations"
  ([arXiv:2610.08144](https://arxiv.org/abs/2610.08144), 6 Oct 2026). NL means natural language: the proof as written
  in words.
- On 15 Oct 2026 the Simons Foundation, Anthropic and OpenAI announced $15 million in combined funding and resources
  for workshops and initiatives that help researchers evaluate AI-assisted results, use new tools and shape standards
  ([announcement](https://www.simonsfoundation.org/?p=61382)).
- The Ledger has 27 entries whose evidence is "formally-verified" (counted on 19 Oct). Examples:
  `matrix-multiplication-omega-nine-fourths-lean`, `openai-quasi-riemann-hypothesis-7-8`,
  `3sum-apsp-exponents-community-lean`, `exact-dft-lean-record-shea-kothe` and `equational-theories-project`.

From the scouting report, not yet re-checked:

- Independent recounts put the formalised share at 24% (173 of 719 manuscripts) or 36% (135 of 372 families), and
  note that "top-line" is not defined
  ([dev.to post, 14 Oct](https://dev.to/getpack/maths-openai-posted-722-ai-proofs-42-machine-checked-3lbb)).
- The release metadata reads review.status "unchecked"
  ([Pebblous audit](https://blog.pebblous.ai/report/openai-math-722-verification-ledger/en/)).
- The release includes 23 Erdős results. Thomas Bloom reportedly said he had not checked that their Lean files
  compile, or that the formal statements capture the problems. The Lean file for Problem 3 proves only a weaker bound
  ([OfficeChai, 9 Oct](https://officechai.com/ai/openai-has-also-included-proofs-for-23-erdos-problems-in-its-latest-math-proof-drop/),
  a secondary source).
- Google DeepMind's formal-conjectures
  [pull request #6898](https://github.com/google-deepmind/formal-conjectures/pull/6898), merged on 11 Oct, linked
  about 25 to 29 openai/math results. It flagged gaps between the formal statements and the problems for Borsuk,
  Green 42, Erdős 371, 952 and 1150, and circulant Hadamard.

The full notes, with every source, are in [notes/scouting-2026-10-19.md](notes/scouting-2026-10-19.md).

## Who else is working on this

From the scouting report, not yet re-checked:

- [Big O Speedrun](https://bigospeedrun.com/about) runs Lean's Comparator against fixed statements for 20 problems.
  It does not compare those statements with the papers.
- The [Palomar registry](https://palomar-registry.org/about), run by the Lean FRO (the organisation that develops Lean) and
  ICARM, registers only what authors submit. It uses a language model to judge whether a formal statement is faithful.
- queelius/openai-math-counterexamples re-computes OpenAI's 63 counterexample families: 8 hold, 0 fail, and the rest
  are not explicit or not finite.
- No systematic audit across labs of whether formal statements match their papers was found.
- Foundation0 members already build on openai/math families 107, 130, 160, 161 and 167
  ([machine mathematics](https://fdn0.org/research/machine-mathematics/)).

The funding announced on 15 Oct makes similar checks by other groups likely.

## How a result is checked

For each claim:

1. Pin the source at a commit.
2. Build the proof and record the axioms it uses. Lean's `#print axioms` lists the basic assumptions a proof rests
   on. A proof that uses `sorryAx` (a step left unproved) or an added axiom proves less than it seems.
3. Take an independent formal statement of the same claim: from
   [formal-conjectures](https://github.com/google-deepmind/formal-conjectures), or written from the paper without
   looking at the lab's version. Record who wrote it, because an independent statement can be wrong too: Erdős #124's
   formal statement once had a typo.
4. Compare the two statements with Lean's [Comparator](https://github.com/leanprover/comparator) or a short bridge
   lemma. Comparator checks that a proof proves a fixed statement and uses only allowed axioms. A bridge lemma is a
   short Lean proof that one statement implies the other.
5. Give a verdict: faithful, weaker, stronger, different, or does not build. Each claim gets one file in
   [verdicts/](verdicts/README.md), with the commit, both statements and the command output.
6. A person who knows the field reviews every verdict other than "faithful" before it is reported.

A finding says "the formal statement differs from the paper's claim", never "the proof is wrong". Like every result
from this repository, a verdict starts with the status "claimed".

## How to contribute

The lead is to be named, and a person signs for every result.

- People and agents: read [AGENTS.md](AGENTS.md), then pick an
  [open issue](https://github.com/Foundation-0/formal-claims-audit/issues).
- New to Foundation0: start with [JOIN.md](https://github.com/Foundation-0/f0/blob/main/JOIN.md).
- Agents split up and hand off work in [st0a](https://github.com/Foundation-0/st0a). Questions and ideas go to the
  [forum](https://github.com/Foundation-0/f0/discussions).

## Files

| path | what |
|---|---|
| [`AGENTS.md`](AGENTS.md) | the guide for AI agents, which [`CLAUDE.md`](CLAUDE.md) loads for Claude Code |
| [`notes/scouting-2026-10-19.md`](notes/scouting-2026-10-19.md) | the research so far, with every source |
| [`notes/reports/`](notes/reports/README.md) | the complete scouting reports, kept as written, and the fact-check |
| [`verdicts/README.md`](verdicts/README.md) | the format of a verdict file |
| [`.github/`](.github/) | the pull request template and the task form |

## Licence

Apache License 2.0 (see [LICENSE](LICENSE)), as for Foundation0's other repositories.

> The full report of the research agent that scouted mathematics and theoretical computer science for Foundation0 on 19 October 2026, kept as it was written. It is model output: a fact in it was checked against its source only where [fact-check.md](fact-check.md) says so. Paths starting with `scratch/` were the scouting session's temporary folder; see [README.md](README.md) for where those files are now.

# Maths and TCS scouting for Foundation0, 19 Oct 2026

## The field has changed since yesterday's pass

AI-assisted work now covers most short lists of open problems.

- **Records with AI involved.** VibeMathed tracks 1,284 problems, 518 resolved with AI involved ([vibemathed.com](https://vibemathed.com/)).
- **Hadamard matrices.** Alpöge's team with Claude posted Hadamard matrices for all 12 open orders below 2000 on 12 Aug ([Epoch](https://epoch.ai/frontiermath/open-problems/hadamard)).
- **The openai/math release.** OpenAI posted 722 manuscripts on 6 Oct ([openai/math](https://github.com/openai/math)).
- **Benchmarks** now include MOLS, covering designs and degree–diameter graphs ([Endless Exam, 2609.24555](https://arxiv.org/html/2609.24555)).

What still looks overlooked:

- checking whether the formal statements of AI claims match the papers;
- unpublished old records nobody has re-checked;
- a few geometry tables that have been quiet since about 2020.

## Candidates, ranked

### 1. `openai-math-fidelity`

**Question.** For each Lean-checked main result in openai/math, does the Lean statement say what the paper's headline claims?

**Why now**
- The formalisation catalogue grew from 162 to 173 entries by 13 Oct.
- The release's own metadata still reads `review.status: "unchecked"`, and no statement-fidelity review has been done ([Pebblous audit](https://blog.pebblous.ai/report/openai-math-722-verification-ledger/en/)).
- Simons, OpenAI and Anthropic announced a $15M effort on 15 Oct to fund checking of AI-generated results ([coverage](https://yourstory.com/ai-story/ai-in-mathematics-15m-simons-openai-anthropic)).
- f0's own "After the 722" page (`docs/research/machine-mathematics`) lists statement fidelity as the open question even for the Lean-checked Fourier record. Five of the six refinements on that page stand only on unreviewed manuscripts.

**Who else**
- Bastounis, Circelli and Hansen checked one case, Navier–Stokes, and found mismatches ([2610.08144](https://arxiv.org/abs/2610.08144)).
- formal-conjectures PR #6898 (merged 11 Oct) linked about 25–29 results. It flagged statement gaps for Borsuk, Green 42, Erdős 371/952/1150 and circulant Hadamard ([PR](https://github.com/google-deepmind/formal-conjectures/pull/6898)).
- queelius/Pico re-computes the 63 counterexample families: 8 hold, 0 fail, the rest are not explicit or not finite ([repo](https://github.com/queelius/openai-math-counterexamples)). That is a computation census, not a fidelity review.
- No systematic fidelity audit found.

**How it is checked.** Anyone can:
- rebuild each theorem with OpenAI's comparator and print its axioms;
- read a side-by-side table of the formal statement against the paper's claim, with a verdict (faithful, weaker, different);
- check the small Lean bridge lemmas where needed, as the PR did for circulant Hadamard.

**First step.** Audit the Lean-linked families f0 members already build on: 107, 130, 160, 161 and 167. Record which have actual catalogue proofs rather than only scope documents, and publish five verdicts.

**Data and tools.** openai/math (Apache-2.0), Lean 4 and Mathlib, formal-conjectures.

**Fits.** rohanarun (refinements of 160, 161, 167 and 107), Ryan Shea (Lean Fourier record), Ahraz/Aska (the Ledger and the "After the 722" page).

**Risks**
- Fast crowding from Simons-funded groups, or OpenAI publishing its own review.
- Verdicts need judgement from someone in the field.
- AHM-style backlash.
- Kill: OpenAI or formal-conjectures publishes a full fidelity table first.

### 2. `covering-min-modulus`

**Question.** Is there a covering system with distinct moduli, all at least 43? Independently, does Owens's record of 42 actually check out?

**Why now**
- The record of 42 comes from Owens's 2014 BYU master's thesis ([etd/4329](https://scholarsarchive.byu.edu/etd/4329)).
- I found no journal version and no independent verification. One paper marks the attribution "(???)" ([1905.07386](https://arxiv.org/pdf/1905.07386)).
- The upper bound is 616,000. Erdős Problem #2 (page last edited 5 Apr 2026) names one person working on it and one formaliser ([erdosproblems #2](https://www.erdosproblems.com/2)). The forum thread holds only three comments from Oct 2025, none about constructions.

**Who else.** Nothing in 2025–26 beyond a 2024 paper citing 42 ([2407.15280](https://arxiv.org/pdf/2407.15280)). Searched arXiv and the web for "minimum modulus" 43, Owens and covering systems.

**How it is checked.**
- The certificate is a list of congruences.
- Two independent programs confirm the cover using the Chinese remainder theorem over the prime factors of the lcm.
- A Lean-checked checker is possible.

**First step.** Get the thesis PDF (BYU blocked automated download, so this is unverified) and transcribe the system. Write two coverage checkers and confirm or refute 42, then Nielsen's 40. A confirmation alone is a Ledger entry.

**Fits.** rohanarun (the auto-research agent on an open problem), Ahraz's exact-search-plus-exhaustive-check pattern.

**Risks**
- 43 may need an lcm far beyond reach.
- Erdős-problem watchers may join.
- Kill: someone has already verified 42 publicly. If 42 turns out wrong, that is itself a result.

### 3. `rectilinear-crossings`

**Question.** Is the rectilinear crossing number of K₂₈ 7233 or 7234? Can better point sets push the asymptotic constant below 0.380449189?

**Why now**
- n = 28 has been "either 7233 or 7234" since 2008 ([OEIS A014540](https://oeis.org/A014540); [MathWorld](https://mathworld.wolfram.com/RectilinearCrossingNumber.html)).
- Exact values are known for n ≤ 27 and n = 30 ([survey](https://www.csun.edu/~sf70713/publications/survey.pdf)).
- The constant's upper bound dates from 2019, in a paper last revised in 2020 ([1907.07796](https://arxiv.org/abs/1907.07796)). The best set (2,643 points) can be downloaded ([crossingnumbers.org](https://www.crossingnumbers.org/projects/crossingconstants/rectilinear.php)).

**Who else**
- No 2024–26 arXiv paper improves a specific n or the constant. I screened the 25 newest of 55 arXiv results for "rectilinear crossing number".
- The topic is not among the 14 Endless Exam families.
- The maintainers are Aichholzer's TU Graz group. Their pages returned 503 today, so the table's date is unverified.

**How it is checked.** The certificate is a point file. Crossings are counted with exact integer orientation tests. The constant follows from the paper's duplication formula, which needs checking first.

**First step.** Write an exact counter, reproduce the 2,643-point bound, then run GPU annealing on n = 28, seeded from the best 28- and 30-point sets.

**Fits.** Ahraz (incentre-lattice geometry), Ryan Shea (rented GPUs).

**Risks**
- Decades of heuristic search have already been spent here.
- The truth for K₂₈ is probably 7234, and only a new lower-bound proof would settle that.
- Gains in the constant may be tiny.
- Kill: the maintainers hold unpublished improvements.

### 4. `central-configs-n8`

**Question.** Exactly how many planar central configurations do 8 equal masses have, with a computer-certified proof?

**Why now**
- Moczurad and Zgliczyński certified n = 5, 6, 7. n = 7 took about 100 hours, and they wrote that n = 8 was out of reach because of the "dimensionality curse" ([1812.07279](https://arxiv.org/abs/1812.07279)).
- Tomar settled four-body convex uniqueness for all masses with interval arithmetic plus Lean on 28 Sep 2026 ([2609.35632](https://arxiv.org/abs/2609.35632)). The method is current.

**Who else.** No n = 8 listing in 2023–26 arXiv results. Tomar is the nearest active worker.

**How it is checked.** A list of certified solution boxes, plus a certificate that no other region holds a solution, re-run by two programs. This is the same pattern as point-charges.

**First step.** Reproduce n = 5 and n = 6 independently. Time a symmetry-reduced or homotopy-plus-certification approach at n = 7.

**Fits.** The point-charges team (Ahraz and Claude).

**Risks.** The authors estimate about 4×10⁴ times more boxes per extra body. Kill: n = 7 cannot be reproduced at least 10 times faster.

## Status of yesterday's three leads

**Linear codes over GF(3)–GF(9): still open.**
- codetables.de's newest dated update is 24 May 2024, for quantum codes ([main page](https://www.codetables.de/main.html)).
- Grassl's 2025–26 arXiv papers are on other topics ([listing](https://arxiv.org/a/grassl_m_1)).
- One small entrant: genetic-algorithm records over F₃ and F₄, 19 Aug 2026 ([2608.18664](https://arxiv.org/abs/2608.18664)). No sweep announced.
- His own quasi-cyclic sweep cannot be seen from outside.

**OEIS Hardin "Empirical" recurrences: still open, one new entrant.**
- The counts are unchanged: 16,180 entries, 16 "proved", 128 Howroyd ([search](https://oeis.org/search?q=author%3AHardin+Empirical&fmt=short)).
- Howroyd confirmed A239040 by the transfer method on 22 Jan 2026.
- Hetark Shah posted five Lean 4 repositories on 12 Oct 2026, described as AI-assisted by Grok. They prove Hardin recurrences for A245995, A246479, A246483–6, A246737 and A188866 ([profile](https://github.com/het4rk?tab=repositories)). I have not verified them.
- Contact him before choosing a family.

**Circulant weighing matrices: still open.**
- Gordon's page footer reads "last updated 2026-09-03", with no changelog ([page](https://dmgordon.org/circulant-weighing-matrices/)).
- Recent work: Tan proved 8 cases impossible ([2608.18468](https://arxiv.org/abs/2608.18468)), and Gordon revised his relative-difference-set paper on 8 Apr 2026 ([2501.14924](https://arxiv.org/abs/2501.14924)).
- No sweep found. Re-download the dataset, because the September update may have changed the open count.

## Rejected as crowded

- **Re-computing openai/math counterexamples:** queelius/Pico has classified all 63, and formal-conjectures has linked the main ones.
- **Hadamard matrices below order 2000:** Alpöge's team (with Claude); verified by VibeMathed.
- **Legendre pairs:** sweeps in July–Sept 2026 ([2609.04589](https://arxiv.org/abs/2609.04589), [2609.25573](https://arxiv.org/abs/2609.25573), [2607.20765](https://arxiv.org/abs/2607.20765)).
- **Snake-in-the-box:** [2607.15270](https://arxiv.org/pdf/2607.15270), [2609.27483](https://arxiv.org/pdf/2609.27483).
- **No-three-in-line:** solved for all n ≤ 60 in Feb 2026 ([2602.07751](https://www.arxiv.org/pdf/2602.07751)).
- **Kobon triangles:** [2507.07951](https://arxiv.org/pdf/2507.07951), [2604.22035](https://arxiv.org/pdf/2604.22035), [2607.29236](https://arxiv.org/pdf/2607.29236).
- **Dimer constant of the cubic lattice:** new upper bound in July 2026 ([2607.28810](https://arxiv.org/pdf/2607.28810)).
- **Exact selection comparisons V_i(n):** Stuttgart group ([SEA 2025](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SEA.2025.16)).
- **Small 5-chromatic unit-distance graphs:**
  - Haugland, 2026 ([2608.04542](https://arxiv.org/abs/2608.04542));
  - an Oct 2026 preprint ([preprints.org](https://www.preprints.org/manuscript/202610.0589));
  - OpenAI family 158, which claims the plane cannot be 5-coloured.
- **Heesch number 7:** on Epoch's open-problem list ([Epoch](https://epoch.ai/frontiermath/open-problems/heesch-number)).
- **MOLS:** an Endless Exam family, and Abel's group is active ([2412.00480](https://arxiv.org/pdf/2412.00480)).
- **Constant-dimension subspace codes:** steady papers through 2025 ([2510.27071](https://arxiv.org/abs/2510.27071)). The site returned 503.
- **Formalising the unit-distance disproof:** Kim Morrison's Lean version of Alpöge's argument exists ([Reservoir](https://reservoir.lean-lang.org/@kim-em/ErdosUnitDistance)).
- **Circuit sizes of small symmetric Boolean functions:** quiet, with no public table (Kulikov's [repo](https://github.com/alexanderskulikov/circuit_improvement)). Low pull outside f0, so set aside rather than crowded.

Downloaded data I used is in `scratch/dl_contents/CONTENTS.md`, a copy of openai/math's index of 372 families.

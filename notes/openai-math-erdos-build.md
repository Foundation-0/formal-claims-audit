# Build evidence contract

The JSON inventory pins the source and toolchain but contains no build results. The root recursive GitHub tree was truncated, so it cannot establish a complete theorem inventory. Catalogue scope pages are the next acquisition step.

## Regenerating the pin

Source: [openai/math](https://github.com/openai/math) at commit `7ef5c0cc5ca4b0e072b7a050fca09ab24bc6fa3a`.

- `CONTENTS.md` lives at the **repository root** (`CONTENTS.md`), not under `lean/docs/`.
- The Lean toolchain file is `lean/lean-toolchain` (there is no root-level `lean-toolchain` at this commit).

```bash
python3 scripts/inventory_erdos.py \
  /path/to/openai-math/CONTENTS.md \
  --commit 7ef5c0cc5ca4b0e072b7a050fca09ab24bc6fa3a \
  --toolchain /path/to/openai-math/lean/lean-toolchain \
  > notes/openai-math-erdos-build.json
```

The build worker must use a disposable container or VM with no credentials or host home mounted. Pin its image digest, copy the source at the recorded commit, populate dependencies separately, then disable network access for the actual build. Give it explicit memory, CPU and time limits. Untrusted lake files can execute code.

For each selected theorem, retain the full Lean declaration name, file, toolchain, exact build command, exit status and #print axioms output. Flag sorryAx and every axiom outside propext, Classical.choice and Quot.sound. A timeout is unresolved, not a mathematical verdict. Another worker must replay a sample before any comparison is published.

# Build evidence contract

The JSON inventory pins the source and toolchain but contains no build results. The root recursive GitHub tree was truncated, so it cannot establish a complete theorem inventory. Catalogue scope pages are the next acquisition step.

The build worker must use a disposable container or VM with no credentials or host home mounted. Pin its image digest, copy the source at the recorded commit, populate dependencies separately, then disable network access for the actual build. Give it explicit memory, CPU and time limits. Untrusted lake files can execute code.

For each selected theorem, retain the full Lean declaration name, file, toolchain, exact build command, exit status and #print axioms output. Flag sorryAx and every axiom outside propext, Classical.choice and Quot.sound. A timeout is unresolved, not a mathematical verdict. Another worker must replay a sample before any comparison is published.

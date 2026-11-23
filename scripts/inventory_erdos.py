#!/usr/bin/env python3
"""Inventory catalogue candidates from a local pinned CONTENTS.md, without building code."""
import argparse
import json
import re

SELECTION = "catalogue text mentions Erdos; incomplete problem-number census"

p = argparse.ArgumentParser(description=__doc__)
p.add_argument(
    "contents",
    help="Path to openai/math CONTENTS.md at the repository root (not lean/docs/CONTENTS.md)",
)
p.add_argument("--commit", required=True, help="Full 40-character source commit SHA")
p.add_argument(
    "--toolchain",
    required=True,
    help="Path to the pinned lean-toolchain file (openai/math uses lean/lean-toolchain)",
)
a = p.parse_args()
if not re.fullmatch("[0-9a-f]{40}", a.commit):
    p.error("full source commit required")
toolchain = open(a.toolchain, encoding="utf-8").read().strip()
if not toolchain:
    p.error("lean-toolchain file is empty")
s = open(a.contents, encoding="utf-8").read()
rows = []
for m in re.finditer(r"^\*\*(\d+)\. (.+?)\*\*(.*)$", s, re.M):
    n, title, tail = m.groups()
    if re.search("erd[oő]s", title + " " + tail, re.I):
        rows.append(
            {
                "catalog_number": int(n),
                "title": title,
                "scope_pages": re.findall(r"\]\((lean/docs/[^)]+)\)", tail),
                "build": "not-run",
                "axioms": None,
            }
        )
out = {
    "source_commit": a.commit,
    "toolchain": toolchain,
    "selection": SELECTION,
    "records": rows,
}
print(json.dumps(out, indent=2, ensure_ascii=True))
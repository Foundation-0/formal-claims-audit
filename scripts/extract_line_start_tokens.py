#!/usr/bin/env python3
"""Extract line_start_tokens from pinned Lean sources (see notes/RULE.md)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "notes" / "family-source-inventory.json"
DEFAULT_SOURCES = ROOT / "notes" / "pinned-sources"

_LINE_PREFIX = re.compile(r"^[\t ]*(?:@\[[^\]]*\][\t ]*)*")
_MODIFIER = re.compile(r"^(private|protected|unsafe|noncomputable)\s+")
_DECLARATION = re.compile(r"^(theorem|lemma|def|abbrev)\s+([A-Za-z_][\w.]*)")


def declaration_name_on_line(line: str) -> str | None:
    """Return the declaration identifier on this line, or None."""
    match = _DECLARATION.match(_declaration_rest(line))
    if match is None:
        return None
    return match.group(2)


def _declaration_rest(line: str) -> str:
    rest = _LINE_PREFIX.match(line)
    text = line[rest.end() :] if rest else line
    while True:
        text = text.lstrip()
        mod = _MODIFIER.match(text)
        if mod is None:
            return text
        text = text[mod.end() :]


def extract_tokens(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for line in text.splitlines():
        name = declaration_name_on_line(line)
        if name is None:
            continue
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_source(sources_root: Path, record_path: str) -> Path:
    return sources_root / record_path


def tokens_for_record(sources_root: Path, record: dict) -> list[str]:
    path = resolve_source(sources_root, record["path"])
    if not path.is_file():
        raise FileNotFoundError(f"missing pinned source: {path}")
    expected = record.get("sha256")
    if expected:
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(
                f"sha256 mismatch for {record['path']}: expected {expected}, got {actual}"
            )
    return extract_tokens(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="family-source-inventory.json path",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=DEFAULT_SOURCES,
        help="root directory containing pinned .lean files",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON mapping path -> token list",
    )
    parser.add_argument("lean_file", nargs="*", help="optional single .lean file(s) to scan")
    args = parser.parse_args(argv)

    if args.lean_file:
        for lean in args.lean_file:
            text = Path(lean).read_text(encoding="utf-8")
            tokens = extract_tokens(text)
            if args.json:
                print(json.dumps({lean: tokens}, indent=2))
            else:
                for token in tokens:
                    print(token)
        return 0

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    result = {}
    for record in inventory["records"]:
        result[record["path"]] = tokens_for_record(args.sources, record)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for path, tokens in result.items():
            print(path)
            for token in tokens:
                print(f"  {token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
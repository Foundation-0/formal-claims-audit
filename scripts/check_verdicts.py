#!/usr/bin/env python3
"""Check verdict file structure, without executing or judging any proof."""

import argparse
import json
from pathlib import Path
import re
import sys


DEFAULT_DIRECTORY = Path(__file__).resolve().parents[1] / "verdicts"
VERDICTS = {"faithful", "weaker", "stronger", "different", "does not build"}
TEXT_FIELDS = (
    "source_repo", "claim", "claim_link", "command", "output_summary", "reviewer",
)
OBJECT_FIELDS = {
    "lab_statement": ("file", "name", "lean"),
    "independent_statement": ("lean", "source", "author"),
    "tool": ("name", "version", "lean_version"),
}
REQUIRED_FIELDS = (
    "id", "source_commit", "verdict", "axioms", *TEXT_FIELDS, *OBJECT_FIELDS,
)


def unique_object(pairs):
    """Do not silently discard earlier values of duplicate JSON keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"{value} is not a JSON value")


def validate_file(path):
    """Return all structural errors in one UTF-8 JSON verdict file."""
    try:
        with path.open(encoding="utf-8") as source:
            data = json.load(
                source, object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
    except (OSError, ValueError, RecursionError) as error:
        return [f"cannot read verdict JSON: {error}"]

    if not isinstance(data, dict):
        return ["verdict must be a JSON object"]

    errors = [f"{key}: required field is missing" for key in REQUIRED_FIELDS if key not in data]
    file_id = path.name[:-len(".json")]
    if "id" in data and (not file_id or data["id"] != file_id):
        errors.append(f"id: must match the nonempty file name without .json ({file_id!r})")
    if "source_commit" in data:
        commit = data["source_commit"]
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            errors.append("source_commit: must be a 40-character hexadecimal hash")
    if "verdict" in data:
        verdict = data["verdict"]
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            errors.append("verdict: must be one of " + ", ".join(sorted(VERDICTS)))

    for key in TEXT_FIELDS:
        if key in data and data[key] is not None and not isinstance(data[key], str):
            errors.append(f"{key}: must be a string or null")

    for key, members in OBJECT_FIELDS.items():
        if key not in data or data[key] is None:
            continue
        value = data[key]
        if not isinstance(value, dict):
            errors.append(f"{key}: must be an object or null")
            continue
        for member in members:
            if member not in value:
                errors.append(f"{key}.{member}: required field is missing")
            elif value[member] is not None and not isinstance(value[member], str):
                errors.append(f"{key}.{member}: must be a string or null")

    if "axioms" in data and data["axioms"] is not None:
        axioms = data["axioms"]
        if not isinstance(axioms, list) or any(not isinstance(axiom, str) for axiom in axioms):
            errors.append("axioms: must be an array of strings or null")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory", nargs="?", type=Path, default=DEFAULT_DIRECTORY,
        help="directory containing verdicts (*.json); defaults to this repository's verdicts/",
    )
    directory = parser.parse_args(argv).directory
    try:
        # iterdir raises for missing, unreadable or non-directory paths rather
        # than treating a failed scan as an empty, successful check.
        paths = sorted(path for path in directory.iterdir() if path.name.endswith(".json"))
    except OSError as error:
        print(f"{directory}: cannot read verdict directory: {error}", file=sys.stderr)
        return 1

    invalid = 0
    for path in paths:
        errors = validate_file(path)
        if errors:
            invalid += 1
            for error in errors:
                print(f"{path}: {error}", file=sys.stderr)
    if invalid:
        print(f"FAIL: {invalid} of {len(paths)} verdict file(s) invalid.", file=sys.stderr)
        return 1

    print(f"OK: checked {len(paths)} verdict file(s) (structure only).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

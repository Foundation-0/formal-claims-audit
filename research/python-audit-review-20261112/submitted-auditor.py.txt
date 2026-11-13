#!/usr/bin/env python3
"""Static AST Soundness & Anti-Tautology Auditor for Agent-Authored Python Checkers.

Detects empirical verification hazards uncovered during multi-agent formal
verification audits:
1. IDENTICAL_ALPHA_SKELETON: `spec` and `impl` checkers share the same AST
   structure up to local variable renaming (copy-paste tautology).
2. FLOAT_LITERAL / FLOAT_DIVISION: IEEE-754 float literals or `/` float division
   used inside an exact certificate checker (instead of `int` / `Fraction`), or
   nondeterministic `global` / bare `except:` constructs.
3. OPTIMISTIC_TRUE_DEFAULT_F01: Boolean verification flags (`verified`, `valid`,
   `match`, `differential_match`, `ok`) initialized to `True` prior to an `if`
   guard, enabling silent single-oracle pass-through.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Set

PRESERVED_NAMES: Set[str] = {
    "abs", "all", "any", "bin", "bool", "chr", "dict", "divmod", "enumerate",
    "filter", "frozenset", "hex", "int", "isinstance", "len", "list", "map",
    "max", "min", "oct", "ord", "pow", "range", "repr", "reversed", "set",
    "sorted", "str", "sum", "tuple", "zip", "Fraction", "True", "False", "None",
    "ValueError", "AssertionError",
}

SUSPICIOUS_BOOL_NAMES: Set[str] = {
    "verified", "is_verified", "valid", "is_valid", "ok",
    "match", "differential_match", "dual_checked", "passed",
}


def alpha_skeleton_sha256(source: str, preserved_api: Set[str] | None = None) -> str:
    """Compute SHA-256 of an alpha-normalized AST (ignoring docstrings and local variable renames)."""
    tree = ast.parse(source)
    keep = PRESERVED_NAMES | (preserved_api or set())
    id_map: Dict[str, str] = {}

    def canon(name: str) -> str:
        if name in keep:
            return name
        if name not in id_map:
            id_map[name] = f"v{len(id_map)}"
        return id_map[name]

    class Normalizer(ast.NodeTransformer):
        def visit_Module(self, node: ast.Module) -> Any:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            return ast.Module(body=[self.visit(s) for s in body], type_ignores=[])

        def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            args = [ast.arg(arg=canon(a.arg)) for a in node.args.args]
            return ast.FunctionDef(
                name=canon(node.name),
                args=ast.arguments(
                    posonlyargs=[], args=args, vararg=None,
                    kwonlyargs=[], kw_defaults=[], kwarg=None,
                    defaults=[self.visit(d) for d in node.args.defaults],
                ),
                body=[self.visit(s) for s in body],
                decorator_list=[],
                returns=None,
            )

        def visit_Name(self, node: ast.Name) -> Any:
            return ast.Name(id=canon(node.id), ctx=node.ctx)

    norm_tree = Normalizer().visit(tree)
    return hashlib.sha256(ast.dump(norm_tree, include_attributes=False).encode("utf-8")).hexdigest()


def audit_checker_source(source: str, label: str = "<checker>", strict_exact_math: bool = True) -> Dict[str, Any]:
    tree = ast.parse(source, filename=label)
    findings: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if strict_exact_math:
            if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
                findings.append({
                    "rule": "FLOAT_LITERAL_IN_EXACT_CHECKER",
                    "line": getattr(node, "lineno", 0),
                    "detail": f"Floating-point literal {node.value!r} risks rounding drift; use int or fractions.Fraction.",
                })
            elif isinstance(node, ast.Div):
                findings.append({
                    "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                    "line": getattr(node, "lineno", 0),
                    "detail": "True division '/' produces IEEE-754 float; use '//' or fractions.Fraction(num, den).",
                })
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            findings.append({
                "rule": "MUTABLE_GLOBAL_SCOPE",
                "line": getattr(node, "lineno", 0),
                "detail": "Mutable global/nonlocal statement inside checker undermines replay determinism.",
            })
        if isinstance(node, ast.Try):
            for h in node.handlers:
                if h.type is None:
                    findings.append({
                        "rule": "BARE_EXCEPT_SWALLOW",
                        "line": getattr(h, "lineno", 0),
                        "detail": "Bare 'except:' clause can silently swallow assertion or solver failures.",
                    })
        if isinstance(node, ast.FunctionDef):
            stmts = node.body
            for idx, stmt in enumerate(stmts):
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name) and tgt.id.lower() in SUSPICIOUS_BOOL_NAMES:
                            has_later_if = any(isinstance(later, ast.If) for later in stmts[idx + 1:])
                            if has_later_if:
                                findings.append({
                                    "rule": "OPTIMISTIC_TRUE_DEFAULT_F01",
                                    "line": stmt.lineno,
                                    "detail": (
                                        f"Verification flag {tgt.id!r} initialized to True in {node.name}() "
                                        "before conditional branch (fail-open F-01 hazard)."
                                    ),
                                })

    return {
        "label": label,
        "alpha_skeleton_sha256": alpha_skeleton_sha256(source),
        "clean": len(findings) == 0,
        "findings_count": len(findings),
        "findings": findings,
    }


def audit_dual_checkers(
    spec_source: str,
    impl_source: str,
    preserved_api: Set[str] | None = None,
    strict_exact_math: bool = True,
) -> Dict[str, Any]:
    s_rep = audit_checker_source(spec_source, label="spec", strict_exact_math=strict_exact_math)
    i_rep = audit_checker_source(impl_source, label="impl", strict_exact_math=strict_exact_math)
    s_skel = alpha_skeleton_sha256(spec_source, preserved_api=preserved_api)
    i_skel = alpha_skeleton_sha256(impl_source, preserved_api=preserved_api)
    distinct = s_skel != i_skel
    verdict = "PASS" if (distinct and s_rep["clean"] and i_rep["clean"]) else "FAIL"
    return {
        "verdict": verdict,
        "distinct_alpha_skeleton": distinct,
        "spec_skeleton_sha256": s_skel,
        "impl_skeleton_sha256": i_skel,
        "spec_audit": s_rep,
        "impl_audit": i_rep,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit one or two Python verification scripts for soundness hazards.")
    ap.add_argument("spec", type=Path, help="Primary checker / specification Python file")
    ap.add_argument("--independent", type=Path, default=None, help="Optional second independent checker file")
    ap.add_argument("--allow-floats", action="store_true", help="Disable strict exact-arithmetic float check")
    args = ap.parse_args()

    spec_src = args.spec.read_text(encoding="utf-8")
    if args.independent is not None:
        impl_src = args.independent.read_text(encoding="utf-8")
        res = audit_dual_checkers(spec_src, impl_src, strict_exact_math=not args.allow_floats)
        print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == "PASS" else 1

    res = audit_checker_source(spec_src, label=str(args.spec), strict_exact_math=not args.allow_floats)
    print(json.dumps(res, indent=2))
    return 0 if res["clean"] else 1


if ____name__ == "__main__":
      raise SystemExit(main())
    raise SystemExit(main())

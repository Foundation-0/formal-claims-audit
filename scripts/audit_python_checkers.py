#!/usr/bin/env python3
"""Conservative AST pattern scanner; cannot certify soundness or independence.

Reports selected source patterns for human inspection and compares a restricted
Python subset up to local binding renames. Different hashes do not establish
independent implementations, correct mathematics, or acceptance-contract fidelity.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Set

SUSPICIOUS_BOOL_NAMES: Set[str] = {
    "verified", "is_verified", "valid", "is_valid", "ok",
    "match", "differential_match", "dual_checked", "passed",
}


class UnsupportedComparison(ValueError):
    """The source is outside the deliberately restricted comparison subset."""


def alpha_skeleton_sha256(source: str, preserved_api: Set[str] | None = None) -> str:
    """Fingerprint a narrow AST subset with separate module/function bindings.

    Unresolved names, attributes, imports and literal values remain unchanged.
    Unsupported binding constructs raise rather than yield misleading hashes.
    """
    tree = ast.parse(source)
    keep = preserved_api or set()
    for node in ast.walk(tree):
        spelling = ''
        if isinstance(node, ast.Name):
            spelling = node.id
        elif isinstance(node, ast.arg):
            spelling = node.arg
        elif isinstance(node, ast.FunctionDef):
            spelling = node.name
        if spelling.startswith(('__function_', '__local_')):
            raise UnsupportedComparison("identifier uses reserved normalization prefix")

    def without_docstring(body: list) -> list:
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            return body[1:]
        return body

    tree.body = without_docstring(tree.body)
    if any(not isinstance(n, (ast.FunctionDef, ast.Import, ast.ImportFrom)) for n in tree.body):
        raise UnsupportedComparison("module body supports only imports and function definitions")
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    names = [n.name for n in functions]
    if len(names) != len(set(names)):
        raise UnsupportedComparison("redefined module functions")
    imported = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    raise UnsupportedComparison("wildcard import")
                imported.add(alias.asname or alias.name.split('.')[0])
    if imported.intersection(names):
        raise UnsupportedComparison("import/function binding collision")
    module_bindings = {name: f"__function_{i}" for i, name in enumerate(names) if name not in keep}

    class Normalizer(ast.NodeTransformer):
        def __init__(self) -> None:
            self.locals: Dict[str, str] = {}

        def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
            args = node.args
            if (args.posonlyargs or args.vararg or args.kwarg or args.kwonlyargs
                    or args.defaults or node.decorator_list or node.returns
                    or node.type_comment or getattr(node, 'type_params', [])
                    or any(a.annotation or a.type_comment for a in args.args)):
                raise UnsupportedComparison("decorated, annotated or non-simple function signature")
            forbidden = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                         ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
                         ast.GeneratorExp, ast.NamedExpr, ast.Global, ast.Nonlocal,
                         ast.Import, ast.ImportFrom, ast.Delete, ast.AnnAssign)
            for stmt in node.body:
                for child in ast.walk(stmt):
                    if isinstance(child, forbidden):
                        raise UnsupportedComparison(f"unsupported binding construct: {type(child).__name__}")
                    if isinstance(child, ast.ExceptHandler) and child.name:
                        raise UnsupportedComparison("exception target binding")
                    if isinstance(child, ast.Call) and child.keywords:
                        raise UnsupportedComparison("keyword argument binding")
                    if type(child).__name__.startswith(('Match', 'TypeAlias', 'TypeVar', 'ParamSpec')):
                        raise UnsupportedComparison("pattern matching or type-parameter binding")
            local_names = [a.arg for a in args.args]
            for stmt in node.body:
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store) and child.id not in local_names:
                        local_names.append(child.id)
            self.locals = {name: f"__local_{i}" for i, name in enumerate(local_names) if name not in keep}
            node.name = module_bindings.get(node.name, node.name)
            for arg in args.args:
                arg.arg = self.locals.get(arg.arg, arg.arg)
            node.body = [self.visit(stmt) for stmt in without_docstring(node.body)]
            self.locals = {}
            return node

        def visit_Name(self, node: ast.Name) -> Any:
            node.id = self.locals.get(node.id, module_bindings.get(node.id, node.id))
            return node

    normalized = Normalizer().visit(tree)
    return hashlib.sha256(ast.dump(normalized, include_attributes=False).encode("utf-8")).hexdigest()


def audit_checker_source(source: str, label: str = "<checker>", strict_exact_math: bool = True) -> Dict[str, Any]:
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        return {"label": label, "status": "INCONCLUSIVE", "findings_count": 0,
                "findings": [], "parse_error": {"line": exc.lineno, "detail": exc.msg}}
    findings: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if strict_exact_math:
            if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
                findings.append({
                    "rule": "FLOAT_LITERAL_IN_EXACT_CHECKER",
                    "line": getattr(node, "lineno", 0),
                    "detail": f"Floating-point literal {node.value!r} risks rounding drift; use int or fractions.Fraction.",
                })
            elif isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, ast.Div):
                findings.append({
                    "rule": "UNTYPED_TRUE_DIVISION",
                    "line": getattr(node, "lineno", 0),
                    "detail": "Inspect operand types for true division: int/int produces float, while Fraction/Fraction stays exact. This scanner does not infer types; changing to // can change the mathematics.",
                })
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            findings.append({
                "rule": "MUTABLE_GLOBAL_SCOPE",
                "line": getattr(node, "lineno", 0),
                "detail": "Inspect global/nonlocal state use; this statement alone does not establish nondeterminism.",
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
                                        "before a conditional branch; inspect control flow for a possible fail-open path."
                                    ),
                                })

    return {
        "label": label,
        "status": "DETECTED" if findings else "NOT_DETECTED",
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
    s_skel = i_skel = None
    reason = None
    try:
        s_skel = alpha_skeleton_sha256(spec_source, preserved_api=preserved_api)
        i_skel = alpha_skeleton_sha256(impl_source, preserved_api=preserved_api)
    except (UnsupportedComparison, SyntaxError) as exc:
        reason = str(exc)
    distinct = None if reason else s_skel != i_skel
    if reason:
        verdict = "INCONCLUSIVE"
    elif not distinct or s_rep["findings_count"] or i_rep["findings_count"]:
        verdict = "DETECTED"
    else:
        verdict = "NOT_DETECTED"
    return {
        "verdict": verdict,
        "meaning": "Pattern scan only; no certification of soundness or independence.",
        "comparison_status": "INCONCLUSIVE" if reason else ("DIFFERENT" if distinct else "MATCH"),
        "comparison_limit": reason,
        "distinct_alpha_skeleton": distinct,
        "spec_skeleton_sha256": s_skel,
        "impl_skeleton_sha256": i_skel,
        "spec_audit": s_rep,
        "impl_audit": i_rep,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan selected Python source patterns; does not certify soundness or independence.")
    ap.add_argument("spec", type=Path, help="Primary checker / specification Python file")
    ap.add_argument("--independent", type=Path, default=None, help="Optional second checker file for restricted AST comparison")
    ap.add_argument("--allow-floats", action="store_true", help="Disable strict exact-arithmetic float check")
    args = ap.parse_args()

    spec_src = args.spec.read_text(encoding="utf-8")
    if args.independent is not None:
        impl_src = args.independent.read_text(encoding="utf-8")
        res = audit_dual_checkers(spec_src, impl_src, strict_exact_math=not args.allow_floats)
        print(json.dumps(res, indent=2))
        return {"NOT_DETECTED": 0, "DETECTED": 1, "INCONCLUSIVE": 2}[res["verdict"]]

    res = audit_checker_source(spec_src, label=str(args.spec), strict_exact_math=not args.allow_floats)
    print(json.dumps(res, indent=2))
    return {"NOT_DETECTED": 0, "DETECTED": 1, "INCONCLUSIVE": 2}[res["status"]]


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Static AST linter for Python certificate verify.py checkers (not a Lean soundness scanner).

Detects common empirical verification hazards in agent-authored checkers:

1. ``IDENTICAL_ALPHA_SKELETON`` (dual mode): two checkers share the same
   alpha-normalized AST — a cheap copy-paste / rename tautology lint, **not** a
   proof of algorithmic independence. Independence still needs distinct algorithms
   or differential/mutation testing.

2. ``FLOAT_LITERAL`` / ``FLOAT_DIVISION``: IEEE-754 hazards in exact checkers
   (excludes ``pathlib.Path`` ``/`` joins).

3. ``OPTIMISTIC_TRUE_DEFAULT_F01``: fail-open boolean flags initialized to
   ``True`` before a guard that does not set ``False`` on failure.

4. Additional rules: vacuous stubs, bare ``assert``, broad ``except ...: pass``,
   ``eval``, and related patterns documented in ``audit_checker_source``.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
    "certified", "success", "succeeded",
}


def _dump_key(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _is_path_lhs(node: ast.AST) -> bool:
    """True when *node* is likely a pathlib.Path used as the left operand of ``/``."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "Path":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "Path":
            return True
    if isinstance(node, ast.Name) and node.id in ("Path", "ROOT", "path"):
        return True
    if isinstance(node, ast.Attribute) and node.attr in ("parent", "parents", "root"):
        return True
    # Trailing / operator chain: ROOT / "a" / "b"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_path_lhs(node.left) or _is_path_lhs(node.right)
    return False


def _is_pathlike_div(binop: ast.BinOp) -> bool:
    """Heuristic: pathlib joins use ``/`` with a string segment on the right."""
    if isinstance(binop.right, ast.Constant) and isinstance(binop.right.value, str):
        if _is_path_lhs(binop.left):
            return True
        if isinstance(binop.left, ast.BinOp) and isinstance(binop.left.op, ast.Div):
            return _is_pathlike_div(binop.left)
        if isinstance(binop.left, ast.Name):
            return True
    return _is_path_lhs(binop.left)


def _build_parent_map(tree: ast.AST) -> Dict[ast.AST, ast.AST]:
    parents: Dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def alpha_skeleton_sha256(source: str, preserved_api: Set[str] | None = None) -> str:
    """SHA-256 of an alpha-normalized AST (local renames, commutative ops, dead code pruning).

    What this **can** detect: copy-paste checkers after local renames, leading ``pass``,
    commutative ``+`` / ``==``, single-use temp hoisting, and uncalled helper defs stripped.

    What this **cannot** detect: genuinely different algorithms with similar structure,
    semantic equivalence under non-commutative edits, or true dual-checker independence.
    """
    tree = ast.parse(source)
    keep = PRESERVED_NAMES | (preserved_api or set())
    id_map: Dict[str, str] = {}

    def canon(name: str) -> str:
        if name in keep:
            return name
        if name not in id_map:
            id_map[name] = f"v{len(id_map)}"
        return id_map[name]

    class _AlphaNormalizer(ast.NodeTransformer):
        def visit_Module(self, node: ast.Module) -> Any:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    body = body[1:]
            body = [self.visit(s) for s in body]
            body = self._prune_uncalled_functions(body)
            return ast.Module(body=body, type_ignores=[])

        def _prune_uncalled_functions(self, body: List[ast.stmt]) -> List[ast.stmt]:
            funcs = [s for s in body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if len(funcs) <= 1:
                return body
            names = {f.name for f in funcs}
            called: Set[str] = set()
            for f in funcs:
                for sub in ast.walk(f):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        if sub.func.id in names:
                            called.add(sub.func.id)
            # Keep called functions and the largest (likely main checker); drop dead helpers.
            ranked = sorted(funcs, key=lambda f: len(ast.dump(f)), reverse=True)
            kept_names = set(called)
            if ranked:
                kept_names.add(ranked[0].name)
            return [s for s in body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) or s.name in kept_names]

        def _strip_function_body_noise(self, body: List[ast.stmt]) -> List[ast.stmt]:
            out: List[ast.stmt] = []
            for stmt in body:
                if isinstance(stmt, ast.Pass):
                    continue
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    tgt = stmt.targets[0]
                    if isinstance(tgt, ast.Name) and isinstance(stmt.value, ast.Name):
                        if tgt.id == stmt.value.id:
                            continue
                out.append(stmt)
            out = self._inline_single_use_temps(out)
            return out

        def _inline_single_use_temps(self, body: List[ast.stmt]) -> List[ast.stmt]:
            if len(body) < 2:
                return body
            new_body: List[ast.stmt] = []
            i = 0
            while i < len(body):
                stmt = body[i]
                if (
                    i + 1 < len(body)
                    and isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                ):
                    name = stmt.targets[0].id
                    rest = body[i + 1 :]
                    uses = sum(
                        1
                        for sub in ast.walk(body[i + 1])
                        if isinstance(sub, ast.Name) and sub.id == name
                    )
                    if uses == 1 and len(rest) == 1 and isinstance(rest[0], ast.Return):
                        ret = rest[0]
                        if ret.value is not None:

                            class _Replacer(ast.NodeTransformer):
                                def visit_Name(self, n: ast.Name) -> Any:
                                    if n.id == name:
                                        return stmt.value
                                    return n

                            ret = _Replacer().visit(ret)
                            new_body.append(ret)
                            i += 2
                            continue
                new_body.append(self.visit(stmt) if isinstance(stmt, ast.AST) else stmt)
                i += 1
            return new_body

        def _canon_arguments(self, args: ast.arguments) -> ast.arguments:
            return ast.arguments(
                posonlyargs=[ast.arg(arg=canon(a.arg)) for a in args.posonlyargs],
                args=[ast.arg(arg=canon(a.arg)) for a in args.args],
                vararg=ast.arg(arg=canon(args.vararg.arg)) if args.vararg else None,
                kwonlyargs=[ast.arg(arg=canon(a.arg)) for a in args.kwonlyargs],
                kw_defaults=[self.visit(d) if d is not None else None for d in args.kw_defaults],
                kwarg=ast.arg(arg=canon(args.kwarg.arg)) if args.kwarg else None,
                defaults=[self.visit(d) for d in args.defaults],
            )

        def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    body = body[1:]
            body = self._strip_function_body_noise(body)
            canon(node.name)
            canon_args = self._canon_arguments(node.args)
            body = [self.visit(s) for s in body]
            deco = [self.visit(d) for d in node.decorator_list]
            ret_ann = self.visit(node.returns) if node.returns is not None else None
            return ast.FunctionDef(
                name=canon(node.name),
                args=canon_args,
                body=body,
                decorator_list=deco,
                returns=ret_ann,
            )

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
            sync = self.visit_FunctionDef(
                ast.FunctionDef(
                    name=node.name,
                    args=node.args,
                    body=node.body,
                    decorator_list=node.decorator_list,
                    returns=node.returns,
                )
            )
            return ast.AsyncFunctionDef(
                name=sync.name,
                args=sync.args,
                body=sync.body,
                decorator_list=sync.decorator_list,
                returns=sync.returns,
            )

        def _canon_add_operands(self, left: ast.AST, right: ast.AST) -> Tuple[ast.AST, ast.AST]:
            lk, rk = _dump_key(left), _dump_key(right)
            if rk < lk:
                return right, left
            return left, right

        def visit_BinOp(self, node: ast.BinOp) -> Any:
            left = self.visit(node.left)
            right = self.visit(node.right)
            if isinstance(node.op, ast.Add):
                left, right = self._canon_add_operands(left, right)
            return ast.BinOp(left=left, op=node.op, right=right)

        def visit_Compare(self, node: ast.Compare) -> Any:
            if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq) and len(node.comparators) == 1:
                left = self.visit(node.left)
                right = self.visit(node.comparators[0])
                lk, rk = _dump_key(left), _dump_key(right)
                if rk < lk:
                    left, right = right, left
                return ast.Compare(left=left, ops=node.ops, comparators=[right])
            return self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> Any:
            return ast.Name(id=canon(node.id), ctx=node.ctx)

        def visit_Attribute(self, node: ast.Attribute) -> Any:
            return ast.Attribute(value=self.visit(node.value), attr=node.attr, ctx=node.ctx)

        def visit_keyword(self, node: ast.keyword) -> Any:
            return ast.keyword(arg=node.arg, value=self.visit(node.value))

        def visit_Return(self, node: ast.Return) -> Any:
            val = self.visit(node.value) if node.value is not None else None
            return ast.Return(value=val)

    class _AddCanonicalizer(ast.NodeTransformer):
        def visit_BinOp(self, node: ast.BinOp) -> Any:
            node = self.generic_visit(node)
            if isinstance(node.op, ast.Add):
                lk, rk = _dump_key(node.left), _dump_key(node.right)
                if rk < lk:
                    return ast.BinOp(left=node.right, op=node.op, right=node.left)
            return node

    norm_tree = _AddCanonicalizer().visit(_AlphaNormalizer().visit(tree))
    ast.fix_missing_locations(norm_tree)
    dumped = ast.dump(norm_tree, include_attributes=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _assigns_false_to(stmts: List[ast.stmt], var: str) -> bool:
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id == var:
                    if isinstance(stmt.value, ast.Constant) and stmt.value.value is False:
                        return True
                    if isinstance(stmt.value, ast.UnaryOp) and isinstance(stmt.value.op, ast.Not):
                        return True
        if isinstance(stmt, ast.If):
            for branch in (stmt.body, stmt.orelse):
                if _assigns_false_to(branch, var):
                    return True
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.If):
                for branch in (sub.body, sub.orelse):
                    if _assigns_false_to(branch, var):
                        return True
    return False


def _is_optimistic_true_init(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    stmt: ast.stmt,
    idx: int,
) -> bool:
    var: Optional[str] = None
    if isinstance(stmt, ast.Assign):
        if not isinstance(stmt.value, ast.Constant) or stmt.value.value is not True:
            if isinstance(stmt.value, ast.UnaryOp) and isinstance(stmt.value.op, ast.Not):
                if isinstance(stmt.value.operand, ast.Constant) and stmt.value.operand.value is False:
                    pass
                else:
                    return False
            else:
                return False
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name) and tgt.id.lower() in SUSPICIOUS_BOOL_NAMES:
                var = tgt.id
                break
    elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        if stmt.target.id.lower() not in SUSPICIOUS_BOOL_NAMES:
            return False
        val = stmt.value
        if isinstance(val, ast.Constant) and val.value is True:
            var = stmt.target.id
        elif isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not):
            if isinstance(val.operand, ast.Constant) and val.operand.value is False:
                var = stmt.target.id
        else:
            return False
    else:
        return False
    if var is None:
        return False
    rest = func.body[idx + 1 :]
    if not rest:
        return False
    has_guard = any(isinstance(s, ast.If) for s in ast.walk(ast.Module(body=rest, type_ignores=[])))
    if not has_guard:
        return False
    if _assigns_false_to(rest, var):
        return False
    return True


def _is_broad_except_pass(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return _handler_body_swallows(handler)
    if isinstance(handler.type, ast.Name) and handler.type.id in ("Exception", "BaseException"):
        return _handler_body_swallows(handler)
    if isinstance(handler.type, ast.Tuple):
        names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
        if "Exception" in names or "BaseException" in names:
            return _handler_body_swallows(handler)
    return False


def _handler_body_swallows(handler: ast.ExceptHandler) -> bool:
    body = handler.body
    if not body:
        return True
    if len(body) == 1 and isinstance(body[0], ast.Pass):
        return True
    if len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is None:
        return True
    return False


def audit_checker_source(source: str, label: str = "<checker>", strict_exact_math: bool = True) -> Dict[str, Any]:
    tree = ast.parse(source, filename=label)
    findings: List[Dict[str, Any]] = []
    parents = _build_parent_map(tree)

    for node in ast.walk(tree):
        if strict_exact_math:
            if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
                findings.append({
                    "rule": "FLOAT_LITERAL_IN_EXACT_CHECKER",
                    "line": getattr(node, "lineno", 0),
                    "detail": f"Floating-point literal {node.value!r} risks rounding drift; use int or fractions.Fraction.",
                })
            elif isinstance(node, ast.Div):
                parent = parents.get(node)
                if isinstance(parent, ast.BinOp) and parent.op is node:
                    if not _is_pathlike_div(parent):
                        findings.append({
                            "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                            "line": parent.lineno,
                            "detail": "True division '/' produces IEEE-754 float; use '//' or fractions.Fraction(num, den).",
                        })
                elif isinstance(parent, ast.AugAssign) and isinstance(parent.op, ast.Div):
                    if not _is_path_lhs(parent.target):
                        findings.append({
                            "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                            "line": parent.lineno,
                            "detail": "Augmented true division '/=' produces float; use '//=' or int math.",
                        })
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "float":
                    findings.append({
                        "rule": "FLOAT_CALL_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": "float() coercion risks IEEE-754 drift in an exact checker.",
                    })
                if isinstance(node.func, ast.Attribute) and node.func.attr == "sqrt":
                    findings.append({
                        "rule": "FLOAT_SQRT_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": "math.sqrt (or similar) yields float; use exact integer methods.",
                    })
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
                if isinstance(node.right, ast.UnaryOp) and isinstance(node.right.op, ast.USub):
                    findings.append({
                        "rule": "FLOAT_NEGATIVE_EXPONENT",
                        "line": node.lineno,
                        "detail": "Negative exponent often produces float (e.g. 2 ** -1); use exact rationals.",
                    })

        if isinstance(node, (ast.Global, ast.Nonlocal)):
            findings.append({
                "rule": "MUTABLE_GLOBAL_SCOPE",
                "line": node.lineno,
                "detail": "Mutable global/nonlocal statement inside checker undermines replay determinism.",
            })

        if isinstance(node, ast.Try):
            for h in node.handlers:
                if _is_broad_except_pass(h):
                    findings.append({
                        "rule": "BARE_EXCEPT_SWALLOW",
                        "line": h.lineno,
                        "detail": "Bare or broad 'except ...: pass' can silently swallow failures.",
                    })

        if isinstance(node, ast.Assert):
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                findings.append({
                    "rule": "VACUOUS_ASSERT",
                    "line": node.lineno,
                    "detail": "Vacuous assert True is stripped under python -O.",
                })
            else:
                findings.append({
                    "rule": "BARE_ASSERT_STRIPPED_UNDER_O",
                    "line": node.lineno,
                    "detail": "assert may be stripped under python -O; use explicit raises for certificates.",
                })

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            findings.append({
                "rule": "EVAL_CALL",
                "line": node.lineno,
                "detail": "eval() is non-deterministic and unsafe inside verification checkers.",
            })

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stmts = node.body
            for idx, stmt in enumerate(stmts):
                if _is_optimistic_true_init(node, stmt, idx):
                    name = (
                        stmt.targets[0].id
                        if isinstance(stmt, ast.Assign)
                        else stmt.target.id  # type: ignore[union-attr]
                    )
                    findings.append({
                        "rule": "OPTIMISTIC_TRUE_DEFAULT_F01",
                        "line": stmt.lineno,
                        "detail": (
                            f"Verification flag {name!r} initialized to True in {node.name}() "
                            "before conditional branch without fail-closed False assignment (fail-open F-01 hazard)."
                        ),
                    })
            for stmt in stmts:
                if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                    if stmt.value.value is True:
                        non_trivial = [
                            s
                            for s in stmts
                            if not isinstance(s, (ast.Pass, ast.Assert, ast.Return))
                        ]
                        if not non_trivial:
                            findings.append({
                                "rule": "VACUOUS_RETURN_TRUE",
                                "line": stmt.lineno,
                                "detail": "Function returns constant True without verification logic.",
                            })
                        break

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
    ap = argparse.ArgumentParser(description="Audit Python verification checkers (AST linter).")
    ap.add_argument("spec", type=Path, nargs="?", default=None, help="Primary checker file")
    ap.add_argument("impl", type=Path, nargs="?", default=None, help="Second checker (dual mode)")
    ap.add_argument(
        "--single",
        type=Path,
        default=None,
        metavar="FILE",
        help="Audit one checker file (same as positional spec only)",
    )
    ap.add_argument(
        "--dual",
        nargs=2,
        metavar=("SPEC", "IMPL"),
        type=Path,
        default=None,
        help="Audit two checkers for skeleton distinctness",
    )
    ap.add_argument("--independent", type=Path, default=None, help="Legacy alias for second checker")
    ap.add_argument("--allow-floats", action="store_true", help="Disable strict exact-arithmetic float check")
    ap.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Emit JSON on stdout (default; kept for CLI compatibility with PR docs)",
    )
    ap.add_argument("--no-json", action="store_false", dest="json", help="Suppress JSON output")
    args = ap.parse_args()

    strict = not args.allow_floats

    if args.dual is not None:
        spec_path, impl_path = args.dual
        spec_src = spec_path.read_text(encoding="utf-8")
        impl_src = impl_path.read_text(encoding="utf-8")
        res = audit_dual_checkers(spec_src, impl_src, strict_exact_math=strict)
        if args.json:
            print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == "PASS" else 1

    single = args.single or args.spec
    if single is None:
        ap.error("Provide --single FILE, --dual SPEC IMPL, or a positional checker path.")

    impl_path = args.impl or args.independent
    spec_src = single.read_text(encoding="utf-8")

    if impl_path is not None:
        impl_src = impl_path.read_text(encoding="utf-8")
        res = audit_dual_checkers(spec_src, impl_src, strict_exact_math=strict)
        if args.json:
            print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == "PASS" else 1

    res = audit_checker_source(spec_src, label=str(single), strict_exact_math=strict)
    if args.json:
        print(json.dumps(res, indent=2))
    return 0 if res["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
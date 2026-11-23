#!/usr/bin/env python3
"""Static AST linter for Python certificate verify.py checkers (not a Lean soundness scanner).

Detects common empirical verification hazards in agent-authored checkers:

1. ``IDENTICAL_ALPHA_SKELETON`` (dual mode): two checkers share the same
   alpha-normalized AST — a cheap copy-paste / rename tautology lint, **not** a
   proof of algorithmic independence. Independence still needs distinct algorithms
   or differential/mutation testing.

2. ``FLOAT_LITERAL`` / ``FLOAT_DIVISION``: IEEE-754 hazards in exact checkers
   (excludes ``pathlib.Path`` ``/`` joins).

3. ``OPTIMISTIC_TRUE_DEFAULT_F01``: locals initialized to ``True`` (or ``not False``)
   that are returned after guards with no fail-closed ``False`` assignment
   (structural rule; suspicious names only affect the detail string).

4. Additional rules: vacuous stubs, bare ``assert``, broad ``except ...: pass``,
   ``eval``, and related patterns documented in ``audit_checker_source``.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

VERDICT_DISTINCT_LINT_CLEAN = "DISTINCT_LINT_CLEAN"
VERDICT_FAIL = "FAIL"

# math.* attributes allowed in exact checkers (documented in README).
MATH_INT_ONLY_ATTRS: Set[str] = {
    "isqrt", "gcd", "lcm", "comb", "perm", "factorial",
}

PATH_FACTORY_ATTRS: Set[str] = {
    "Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath",
}
PATH_MODULE_NAMES: Set[str] = {"pathlib", "posixpath", "ntpath"}

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


def _is_path_factory_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in PATH_FACTORY_ATTRS:
        return True
    if isinstance(func, ast.Attribute) and func.attr in PATH_FACTORY_ATTRS:
        return True
    return False


def _is_path_like_expr(node: ast.AST) -> bool:
    if _is_path_factory_call(node):
        return True
    if isinstance(node, ast.Name) and node.id in PATH_FACTORY_ATTRS | {"Path", "ROOT", "path", "root"}:
        return True
    if isinstance(node, ast.Attribute) and node.attr in ("parent", "parents", "root"):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_pathlike_div(node)
    return False


def _is_path_lhs(node: ast.AST) -> bool:
    return _is_path_like_expr(node)


def _is_pathlike_div(binop: ast.BinOp) -> bool:
    """Pathlib / PurePath joins: Path/PurePath(...) / segment (literal, name, or nested Path)."""
    if isinstance(binop.left, ast.Name) and isinstance(binop.right, ast.Constant):
        if isinstance(binop.right.value, str):
            return True
    if not _is_path_like_expr(binop.left):
        return False
    right = binop.right
    if isinstance(right, ast.Constant) and isinstance(right.value, str):
        return True
    if isinstance(right, ast.Name):
        return True
    if _is_path_factory_call(right) or _is_path_like_expr(right):
        return True
    if isinstance(binop.left, ast.BinOp) and isinstance(binop.left.op, ast.Div):
        return _is_pathlike_div(binop.left)
    return False


def _is_fraction_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "Fraction":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "Fraction":
        return True
    return False


def _is_decimal_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Decimal":
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Decimal":
        return True
    return False


def _fraction_names_in_scope(stmts: List[ast.stmt]) -> Set[str]:
    names: Set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and _is_fraction_call(stmt.value):
                    names.add(tgt.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None and _is_fraction_call(stmt.value):
                names.add(stmt.target.id)
    return names


def _operand_is_exact_fraction(node: ast.AST, fraction_names: Set[str]) -> bool:
    return _is_fraction_call(node) or (isinstance(node, ast.Name) and node.id in fraction_names)


def _is_exact_fraction_div(binop: ast.BinOp, enclosing_stmts: List[ast.stmt]) -> bool:
    names = _fraction_names_in_scope(enclosing_stmts)
    return _operand_is_exact_fraction(binop.left, names) and _operand_is_exact_fraction(binop.right, names)


def _function_enclosing_stmts(tree: ast.AST, target: ast.AST) -> List[ast.stmt]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if sub is target:
                    return list(node.body)
    if isinstance(tree, ast.Module):
        for sub in ast.walk(tree):
            if sub is target:
                return list(tree.body)
    return []


def _identity_helper_functions(tree: ast.Module) -> Set[str]:
    return {
        stmt.name
        for stmt in tree.body
        if isinstance(stmt, ast.FunctionDef) and _is_single_arg_identity_helper(stmt)
    }


def _is_single_arg_identity_helper(func: ast.FunctionDef) -> bool:
    if func.name in CHECKER_ENTRY_NAMES or func.name.startswith("check") or func.decorator_list:
        return False
    args = func.args.posonlyargs + func.args.args
    if len(args) != 1 or func.args.kwonlyargs or func.args.vararg or func.args.kwarg:
        return False
    body = list(func.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return False
    ret = body[0].value
    return isinstance(ret, ast.Name) and ret.id == args[0].arg


def _inline_identity_call_tree(tree: ast.Module) -> ast.Module:
    helpers = _identity_helper_functions(tree)

    class _Inliner(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> Any:
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in helpers:
                if len(node.args) == 1 and not node.keywords and node.args[0] is not None:
                    return node.args[0]
            return node

    new_body = [_Inliner().visit(stmt) for stmt in tree.body]
    return ast.Module(body=new_body, type_ignores=tree.type_ignores)


def _resolve_local_module_paths(tree: ast.AST, base_dir: Path) -> List[Path]:
    """Resolve relative-to-checker imports to .py files (no stdlib / site-packages)."""
    resolved: List[Path] = []
    if not base_dir.is_dir():
        return resolved

    def add_file(path: Path) -> None:
        if path.is_file() and path.suffix == ".py":
            try:
                path.resolve().relative_to(base_dir.resolve())
            except ValueError:
                return
            if path not in resolved:
                resolved.append(path)

    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if top in sys.stdlib_module_names:
                    continue
                add_file(base_dir / f"{alias.name.replace('.', '/')}.py")
                init = base_dir / alias.name.replace(".", "/") / "__init__.py"
                add_file(init)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                if node.module.split(".", 1)[0] in sys.stdlib_module_names:
                    continue
                add_file(base_dir / f"{node.module.replace('.', '/')}.py")
                add_file(base_dir / node.module.replace(".", "/") / "__init__.py")
            elif node.level:
                rel = ("." * node.level) + (node.module or "")
                # level 1: same directory as checker
                parts = list(base_dir.parts)
                for _ in range(node.level - 1):
                    parts.pop()
                parent = Path(*parts) if parts else base_dir
                if node.module:
                    add_file(parent / f"{node.module.replace('.', '/')}.py")
    return resolved


def _local_import_fingerprint(source: str, source_path: Optional[Path]) -> str:
    if source_path is None:
        return ""
    tree = ast.parse(source, filename=str(source_path))
    base = source_path.resolve().parent
    paths = _resolve_local_module_paths(tree, base)
    if not paths:
        return ""
    chunks: List[str] = []
    for p in sorted(paths, key=lambda x: str(x)):
        try:
            mod_src = p.read_text(encoding="utf-8")
        except OSError:
            continue
        chunks.append(
            f"{p.name}:{alpha_skeleton_sha256(mod_src, source_path=p, include_imports=False)}"
        )
    return "|".join(chunks)


CHECKER_ENTRY_NAMES: Set[str] = {
    "check", "verify", "validate", "run", "audit", "main", "test_checker",
}


def _is_trivial_uncalled_helper(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = list(func.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return False
    ret = body[0].value
    if isinstance(ret, ast.Constant):
        return True
    if isinstance(ret, ast.Name):
        arg_names = [a.arg for a in func.args.posonlyargs + func.args.args]
        if len(arg_names) == 1 and ret.id == arg_names[0]:
            return True
    return False


def _checker_entry_score(func: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    score = 0
    if func.name in CHECKER_ENTRY_NAMES or func.name.startswith("check"):
        score += 1000
    score += len(func.args.posonlyargs + func.args.args) * 10
    if func.args.kwonlyargs:
        score += 5
    for sub in ast.walk(func):
        if isinstance(sub, ast.Compare):
            score += 50
        if isinstance(sub, ast.For) or isinstance(sub, ast.While):
            score += 20
    score += sum(1 for _ in ast.walk(func))
    return score


def _prune_uncalled_module_functions(tree: ast.Module) -> ast.Module:
    """Drop uncalled top-level helpers before alpha-renaming (uses raw identifiers).

    Heuristic when several uncalled functions remain after removing trivial pads
    (identity ``return z``, ``return 0``, etc.): keep the entry with the highest
    ``_checker_entry_score``. This is not proof of which function is the checker;
    it prevents a larger dead helper from splitting the skeleton hash.
    """
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    funcs = [s for s in body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(funcs) <= 1:
        return tree
    names = {f.name for f in funcs}
    called: Set[str] = set()
    for f in funcs:
        for sub in ast.walk(f):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if sub.func.id in names:
                    called.add(sub.func.id)
    uncalled = [f for f in funcs if f.name not in called]
    called_funcs = [f for f in funcs if f.name in called]
    kept_uncalled: List[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for f in uncalled:
        if not _is_trivial_uncalled_helper(f):
            kept_uncalled.append(f)
    if not kept_uncalled:
        kept_uncalled = list(uncalled)
    elif len(kept_uncalled) > 1:
        best = max(kept_uncalled, key=_checker_entry_score)
        kept_uncalled = [best]
    kept_names = {f.name for f in called_funcs + kept_uncalled}
    new_body = [
        s
        for s in body
        if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) or s.name in kept_names
    ]
    return ast.Module(body=new_body, type_ignores=tree.type_ignores)


def alpha_skeleton_sha256(
    source: str,
    preserved_api: Set[str] | None = None,
    source_path: Optional[Path] = None,
    *,
    include_imports: bool = True,
) -> str:
    """SHA-256 of an alpha-normalized AST (local renames, commutative ops, dead code pruning).

    What this **can** detect: copy-paste checkers after local renames, leading ``pass``,
    commutative ``+`` / ``==``, single-use temp hoisting, and uncalled helper defs stripped
    (pruned on raw AST before local renames so dead code cannot shift v0/v1 ids).

    What this **cannot** detect: genuinely different algorithms with similar structure,
    semantic equivalence under non-commutative edits, or true dual-checker independence.
    """
    tree = _prune_uncalled_module_functions(ast.parse(source, filename=str(source_path or "<checker>")))
    identity_helpers = _identity_helper_functions(tree)
    tree = _inline_identity_call_tree(tree)
    tree = ast.Module(
        body=[
            s
            for s in tree.body
            if not (isinstance(s, ast.FunctionDef) and s.name in identity_helpers)
        ],
        type_ignores=tree.type_ignores,
    )
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
            body = [self.visit(s) for s in body if s is not None]
            return ast.Module(body=body, type_ignores=[])

        def _sort_leading_independent_assigns(self, body: List[ast.stmt]) -> List[ast.stmt]:
            split = 0
            while split < len(body) and isinstance(body[split], ast.Assign):
                split += 1
            if split > 1:
                head = sorted(body[:split], key=lambda s: ast.dump(s, include_attributes=False))
                return head + body[split:]
            return body

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
            out = self._sort_leading_independent_assigns(out)
            out = self._inline_single_use_temps(out)
            return out

        def visit_Import(self, node: ast.Import) -> Any:
            return None

        def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
            return None

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
            if type(node.op) is ast.Add:
                left, right = self._canon_add_operands(left, right)
            return ast.BinOp(left=left, op=node.op, right=right)

        def visit_Compare(self, node: ast.Compare) -> Any:
            if len(node.ops) == 1 and type(node.ops[0]) is ast.Eq and len(node.comparators) == 1:
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
            if type(node.op) is ast.Add:
                lk, rk = _dump_key(node.left), _dump_key(node.right)
                if rk < lk:
                    return ast.BinOp(left=node.right, op=node.op, right=node.left)
            return node

    norm_tree = _AddCanonicalizer().visit(_AlphaNormalizer().visit(tree))
    ast.fix_missing_locations(norm_tree)
    dumped = ast.dump(norm_tree, include_attributes=False)
    digest = dumped
    if include_imports and source_path is not None:
        imp = _local_import_fingerprint(source, source_path)
        if imp:
            digest = f"{dumped}\n#imports:{imp}"
    return hashlib.sha256(digest.encode("utf-8")).hexdigest()


def _expr_is_optimistic_true(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Constant) and expr.value is True:
        return True
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        if isinstance(expr.operand, ast.Constant) and expr.operand.value is False:
            return True
    return False


def _var_returned_from_func(func: ast.FunctionDef | ast.AsyncFunctionDef, var: str) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Name) and node.value.id == var:
                return True
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Name) and sub.id == var:
                    return True
    return False


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
        if not _expr_is_optimistic_true(stmt.value):
            return False
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name):
                var = tgt.id
                break
    elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        if stmt.value is None or not _expr_is_optimistic_true(stmt.value):
            return False
        var = stmt.target.id
    else:
        return False
    if var is None:
        return False
    if not _var_returned_from_func(func, var):
        return False
    rest = func.body[idx + 1 :]
    if not rest:
        return False
    has_guard = any(
        isinstance(s, (ast.If, ast.For, ast.While, ast.With, ast.Try))
        for s in ast.walk(ast.Module(body=rest, type_ignores=[]))
    )
    if not has_guard:
        return False
    if _assigns_false_to(func.body[idx + 1 :], var):
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


def _collect_float_division_findings(tree: ast.AST) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if _is_pathlike_div(node):
                continue
            if _is_decimal_expr(node.left) or _is_decimal_expr(node.right):
                out.append({
                    "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                    "line": node.lineno,
                    "detail": "Decimal division rounds; not exact for certificate checkers.",
                })
                continue
            stmts = _function_enclosing_stmts(tree, node)
            if _is_exact_fraction_div(node, stmts):
                continue
            out.append({
                "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                "line": node.lineno,
                "detail": "True division '/' produces IEEE-754 float; use '//' or fractions.Fraction(num, den).",
            })
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Div):
            if _is_path_lhs(node.target):
                continue
            out.append({
                "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                "line": node.lineno,
                "detail": "Augmented true division '/=' produces float; use '//=' or int math.",
            })
    return out


def _collect_math_numpy_findings(tree: ast.AST) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root == "numpy" or alias.name == "numpy":
                    out.append({
                        "rule": "NUMPY_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": "numpy is float-oriented; avoid in exact certificate checkers.",
                    })
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root == "numpy":
                out.append({
                    "rule": "NUMPY_IN_EXACT_CHECKER",
                    "line": node.lineno,
                    "detail": "numpy is float-oriented; avoid in exact certificate checkers.",
                })
            elif node.module == "math":
                for alias in node.names:
                    name = alias.name
                    if name == "*":
                        out.append({
                            "rule": "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            "line": node.lineno,
                            "detail": "from math import * pulls in float routines; use int-only math attrs.",
                        })
                    elif name not in MATH_INT_ONLY_ATTRS:
                        out.append({
                            "rule": "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            "line": node.lineno,
                            "detail": f"math.{name} may produce floats; int-only allowlist applies.",
                        })
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                attr = node.func.attr
                if mod == "math" and attr not in MATH_INT_ONLY_ATTRS:
                    out.append({
                        "rule": "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": f"math.{attr} may produce floats; int-only allowlist applies.",
                    })
                if mod in ("np", "numpy"):
                    out.append({
                        "rule": "NUMPY_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": "numpy call in exact checker.",
                    })
    return out


def audit_checker_source(source: str, label: str = "<checker>", strict_exact_math: bool = True) -> Dict[str, Any]:
    tree = ast.parse(source, filename=label)
    findings: List[Dict[str, Any]] = []

    if strict_exact_math:
        findings.extend(_collect_float_division_findings(tree))
        findings.extend(_collect_math_numpy_findings(tree))

    for node in ast.walk(tree):
        if strict_exact_math:
            if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
                findings.append({
                    "rule": "FLOAT_LITERAL_IN_EXACT_CHECKER",
                    "line": getattr(node, "lineno", 0),
                    "detail": f"Floating-point literal {node.value!r} risks rounding drift; use int or fractions.Fraction.",
                })
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "float":
                    findings.append({
                        "rule": "FLOAT_CALL_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": "float() coercion risks IEEE-754 drift in an exact checker.",
                    })
            elif isinstance(node, ast.BinOp) and type(node.op) is ast.Pow:
                if isinstance(node.right, ast.UnaryOp) and isinstance(node.right.op, ast.USub):
                    findings.append({
                        "rule": "FLOAT_NEGATIVE_EXPONENT",
                        "line": node.lineno,
                        "detail": "Negative exponent often produces float (e.g. 2 ** -1); use exact rationals.",
                    })
                elif not isinstance(node.right, ast.Constant):
                    findings.append({
                        "rule": "FLOAT_NON_LITERAL_EXPONENT",
                        "line": node.lineno,
                        "detail": "Exponent is not a literal; ** may yield float in exact checkers.",
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
                    name_hint = (
                        " (name matches verification-flag pattern)"
                        if name.lower() in SUSPICIOUS_BOOL_NAMES
                        else ""
                    )
                    findings.append({
                        "rule": "OPTIMISTIC_TRUE_DEFAULT_F01",
                        "line": stmt.lineno,
                        "detail": (
                            f"Flag {name!r} initialized optimistically in {node.name}(), returned after "
                            f"guards with no fail-closed False assignment (fail-open F-01 hazard){name_hint}."
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
    spec_path: Optional[Path] = None,
    impl_path: Optional[Path] = None,
) -> Dict[str, Any]:
    s_rep = audit_checker_source(spec_source, label="spec", strict_exact_math=strict_exact_math)
    i_rep = audit_checker_source(impl_source, label="impl", strict_exact_math=strict_exact_math)
    s_skel = alpha_skeleton_sha256(spec_source, preserved_api=preserved_api, source_path=spec_path)
    i_skel = alpha_skeleton_sha256(impl_source, preserved_api=preserved_api, source_path=impl_path)
    distinct = s_skel != i_skel
    shared_local: List[str] = []
    if spec_path is not None and impl_path is not None:
        spec_tree = ast.parse(spec_source, filename=str(spec_path))
        impl_tree = ast.parse(impl_source, filename=str(impl_path))
        spec_locals = {
            str(p.resolve()) for p in _resolve_local_module_paths(spec_tree, spec_path.resolve().parent)
        }
        impl_locals = {
            str(p.resolve()) for p in _resolve_local_module_paths(impl_tree, impl_path.resolve().parent)
        }
        shared_local = sorted(spec_locals & impl_locals)
        if shared_local:
            distinct = False
    clean = s_rep["clean"] and i_rep["clean"]
    verdict = VERDICT_DISTINCT_LINT_CLEAN if (distinct and clean) else VERDICT_FAIL
    return {
        "verdict": verdict,
        "distinct_alpha_skeleton": distinct,
        "shared_local_modules": shared_local,
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
        res = audit_dual_checkers(
            spec_src, impl_src, strict_exact_math=strict, spec_path=spec_path, impl_path=impl_path,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == VERDICT_DISTINCT_LINT_CLEAN else 1

    single = args.single or args.spec
    if single is None:
        ap.error("Provide --single FILE, --dual SPEC IMPL, or a positional checker path.")

    impl_path = args.impl
    spec_src = single.read_text(encoding="utf-8")

    if impl_path is not None:
        impl_src = impl_path.read_text(encoding="utf-8")
        res = audit_dual_checkers(
            spec_src,
            impl_src,
            strict_exact_math=strict,
            spec_path=single,
            impl_path=impl_path,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == VERDICT_DISTINCT_LINT_CLEAN else 1

    res = audit_checker_source(spec_src, label=str(single), strict_exact_math=strict)
    if args.json:
        print(json.dumps(res, indent=2))
    return 0 if res["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
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
FRACTION_MODULE_NAMES: Set[str] = {"fractions"}

# math.* attributes allowed in exact checkers (documented in README).
MATH_INT_ONLY_ATTRS: Set[str] = {
    "isqrt", "gcd", "lcm", "comb", "perm", "factorial",
}

PATH_FACTORY_ATTRS: Set[str] = {
    "Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath",
}
PATH_MODULE_NAMES: Set[str] = {"pathlib", "posixpath", "ntpath"}
FLOATY_MODULE_ROOTS: Set[str] = {"math", "cmath", "statistics", "numpy"}
FRACTION_CANON = "Fraction"

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


def _fraction_module_bindings(stmts: List[ast.stmt]) -> Set[str]:
    binds: Set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                root = alias.name.split(".", 1)[0]
                if root == "fractions":
                    binds.add(alias.asname or "fractions")
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "fractions":
            for alias in stmt.names:
                if alias.name == "Fraction":
                    binds.add(alias.asname or "Fraction")
    return binds


def _fraction_aliases_from_stmts(stmts: List[ast.stmt]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for stmt in stmts:
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "fractions":
            for alias in stmt.names:
                if alias.name == "Fraction":
                    aliases[alias.asname or alias.name] = FRACTION_CANON
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            tgt = stmt.targets[0].id
            val = stmt.value
            if _is_fraction_call(val, aliases):
                aliases[tgt] = FRACTION_CANON
            elif isinstance(val, ast.Name) and val.id == "Fraction":
                aliases[tgt] = FRACTION_CANON
            elif isinstance(val, ast.Attribute) and val.attr == "Fraction":
                aliases[tgt] = FRACTION_CANON
    return aliases


def _is_fraction_call(
    node: ast.AST,
    aliases: Optional[Dict[str, str]] = None,
    mod_names: Optional[Set[str]] = None,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        if func.id == "Fraction" or (aliases and aliases.get(func.id) == FRACTION_CANON):
            return True
    if isinstance(func, ast.Attribute) and func.attr == "Fraction":
        if isinstance(func.value, ast.Name):
            root = func.value.id
            if root == "fractions" or (mod_names and root in mod_names):
                return True
            if aliases and aliases.get(root) == FRACTION_CANON:
                return True
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
                if isinstance(tgt, ast.Name) and _is_fraction_call(stmt.value, None):
                    names.add(tgt.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None and _is_fraction_call(stmt.value, None):
                names.add(stmt.target.id)
    return names


def _operand_is_exact_fraction(
    node: ast.AST,
    fraction_names: Set[str],
    aliases: Optional[Dict[str, str]] = None,
    mod_names: Optional[Set[str]] = None,
) -> bool:
    return (
        _is_fraction_call(node, aliases, mod_names)
        or (isinstance(node, ast.Name) and node.id in fraction_names)
    )


def _is_exact_fraction_div(binop: ast.BinOp, enclosing_stmts: List[ast.stmt]) -> bool:
    mod_names = _fraction_module_bindings(enclosing_stmts)
    aliases = _fraction_aliases_from_stmts(enclosing_stmts)
    names = _fraction_names_in_scope(enclosing_stmts)
    for stmt in enclosing_stmts:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and _is_fraction_call(stmt.value, aliases, mod_names):
                    names.add(tgt.id)
    return _operand_is_exact_fraction(binop.left, names, aliases, mod_names) and _operand_is_exact_fraction(
        binop.right, names, aliases, mod_names,
    )


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


def _strip_docstring_body(body: List[ast.stmt]) -> List[ast.stmt]:
    body = list(body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    return body


def _param_identity_return_index(func: ast.FunctionDef) -> Optional[int]:
    if func.name in CHECKER_ENTRY_NAMES or func.name.startswith("check") or func.decorator_list:
        return None
    args = func.args.posonlyargs + func.args.args
    if not args or func.args.kwonlyargs or func.args.vararg or func.args.kwarg:
        return None
    body = _strip_docstring_body(list(func.body))
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return None
    ret = body[0].value
    if not isinstance(ret, ast.Name):
        return None
    for i, a in enumerate(args):
        if ret.id == a.arg:
            return i
    return None


def _identity_helper_map(tree: ast.Module) -> Dict[str, int]:
    return {
        stmt.name: idx
        for stmt in tree.body
        if isinstance(stmt, ast.FunctionDef)
        for idx in [_param_identity_return_index(stmt)]
        if idx is not None
    }


def _module_lambda_identity_names(tree: ast.Module) -> Set[str]:
    names: Set[str] = set()
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        tgt = stmt.targets[0]
        val = stmt.value
        if not isinstance(tgt, ast.Name) or not isinstance(val, ast.Lambda):
            continue
        args = val.args.posonlyargs + val.args.args
        if len(args) != 1 or val.args.kwonlyargs or val.args.vararg or val.args.kwarg:
            continue
        if isinstance(val.body, ast.Name) and val.body.id == args[0].arg:
            names.add(tgt.id)
    return names


def _inline_identity_call_tree(
    tree: ast.Module, helpers: Dict[str, int], lambdas: Set[str],
) -> ast.Module:
    class _Inliner(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> Any:
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and not node.keywords:
                if node.func.id in helpers:
                    idx = helpers[node.func.id]
                    if idx < len(node.args) and node.args[idx] is not None:
                        return node.args[idx]
                if node.func.id in lambdas and len(node.args) == 1 and node.args[0] is not None:
                    return node.args[0]
            return node

    new_body = [_Inliner().visit(stmt) for stmt in tree.body]
    return ast.Module(body=new_body, type_ignores=tree.type_ignores)


def _fold_constant_ifs(body: List[ast.stmt]) -> List[ast.stmt]:
    out: List[ast.stmt] = []
    for stmt in body:
        if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Constant):
            if stmt.test.value is True:
                out.extend(stmt.body)
            elif stmt.test.value is False:
                out.extend(stmt.orelse)
            else:
                out.append(stmt)
        else:
            out.append(stmt)
    return out


def _drop_unread_assigns(body: List[ast.stmt]) -> List[ast.stmt]:
    out: List[ast.stmt] = []
    for i, stmt in enumerate(body):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name = stmt.targets[0].id
            used_later = any(
                isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
                for s in body[i + 1 :]
                for n in ast.walk(s)
            )
            if not used_later:
                continue
        out.append(stmt)
    return out


class _AlgebraicFolder(ast.NodeTransformer):
    def _zero_times(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mult)
            and (
                (isinstance(node.left, ast.Constant) and node.left.value == 0)
                or (isinstance(node.right, ast.Constant) and node.right.value == 0)
            )
        )

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        node = self.generic_visit(node)
        if isinstance(node.op, ast.Mult):
            if isinstance(node.left, ast.Constant) and node.left.value == 1:
                return node.right
            if isinstance(node.right, ast.Constant) and node.right.value == 1:
                return node.left
        if isinstance(node.op, ast.Add):
            if self._zero_times(node.left):
                return node.right
            if self._zero_times(node.right):
                return node.left
            if isinstance(node.left, ast.Constant) and node.left.value == 0:
                return node.right
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                return node.left
        if isinstance(node.op, ast.Sub) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            return node.left
        if isinstance(node.op, ast.FloorDiv):
            if isinstance(node.right, ast.Constant) and node.right.value == 1:
                return node.left
            if isinstance(node.left, ast.Constant) and node.left.value == 1:
                return node.right
        return node


class _BoolNoiseFolder(ast.NodeTransformer):
    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        node = self.generic_visit(node)
        if isinstance(node.op, ast.And):
            vals = []
            for v in node.values:
                if isinstance(v, ast.Constant) and v.value is True:
                    continue
                vals.append(v)
            if len(vals) == 1:
                return vals[0]
            if len(vals) != len(node.values):
                return ast.BoolOp(op=node.op, values=vals)
        if isinstance(node.op, ast.Or):
            vals = []
            for v in node.values:
                if isinstance(v, ast.Constant) and v.value is False:
                    continue
                vals.append(v)
            if len(vals) == 1:
                return vals[0]
            if len(vals) != len(node.values):
                return ast.BoolOp(op=node.op, values=vals)
        return node


class _ExprSkeletonFolder(ast.NodeTransformer):
    """Fold walrus, inline IIFEs, and unwrap functools.partial on a return expr."""

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        return self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> Any:
        node = self.generic_visit(node)
        if (
            isinstance(node.func, ast.Lambda)
            and not node.keywords
            and len(node.args) == len(node.func.args.args)
        ):
            lam = node.func
            repl = {a.arg: arg for a, arg in zip(lam.args.args, node.args)}

            class _Sub(ast.NodeTransformer):
                def visit_Name(self, n: ast.Name) -> Any:
                    if n.id in repl:
                        return repl[n.id]
                    return n

            return _Sub().visit(lam.body)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "partial":
            val = node.func.value
            if isinstance(val, ast.Name) and val.id == "partial":
                if len(node.args) == 2 and isinstance(node.args[0], ast.Lambda):
                    lam = node.args[0]
                    if len(lam.args.args) == 2:
                        repl = {lam.args.args[0].arg: node.args[1]}

                        class _Sub(ast.NodeTransformer):
                            def visit_Name(self, n: ast.Name) -> Any:
                                if n.id in repl:
                                    return repl[n.id]
                                return n

                        return _Sub().visit(lam.body)
        if isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Attribute):
            pfn = node.func
            if pfn.func.attr == "partial" and pfn.args and isinstance(pfn.args[0], ast.Lambda):
                lam = pfn.args[0]
                repl: Dict[str, ast.expr] = {}
                for i, b in enumerate(pfn.args[1:]):
                    if i < len(lam.args.args):
                        repl[lam.args.args[i].arg] = b
                for i, a in enumerate(node.args):
                    j = i + len(pfn.args) - 1
                    if j < len(lam.args.args):
                        repl[lam.args.args[j].arg] = a

                class _Sub(ast.NodeTransformer):
                    def visit_Name(self, n: ast.Name) -> Any:
                        if n.id in repl:
                            return repl[n.id]
                        return n

                return _Sub().visit(lam.body)
        return node


def _fold_return_expr(expr: ast.expr) -> ast.expr:
    return _BoolNoiseFolder().visit(
        _ExprSkeletonFolder().visit(_AlgebraicFolder().visit(expr)),
    )


def _fold_stmt_algebra(stmt: ast.stmt) -> ast.stmt:
    if isinstance(stmt, ast.Return) and stmt.value is not None:
        return ast.copy_location(ast.Return(value=_fold_return_expr(stmt.value)), stmt)
    if isinstance(stmt, ast.Assign):
        return ast.copy_location(
            ast.Assign(targets=stmt.targets, value=_fold_return_expr(stmt.value)),
            stmt,
        )
    if isinstance(stmt, ast.Expr):
        return ast.copy_location(ast.Expr(value=_fold_return_expr(stmt.value)), stmt)
    return _AlgebraicFolder().visit(stmt)


def _preprocess_function_body(body: List[ast.stmt]) -> List[ast.stmt]:
    body = _fold_constant_ifs(body)
    body = _drop_unread_assigns(body)
    return [_fold_stmt_algebra(s) for s in body]


def _is_checker_entry(name: str) -> bool:
    return name in CHECKER_ENTRY_NAMES or name.startswith("check")


def _identity_decorator_names(tree: ast.Module) -> Set[str]:
    names: Set[str] = set()
    for stmt in tree.body:
        if not isinstance(stmt, ast.FunctionDef):
            continue
        args = stmt.args.posonlyargs + stmt.args.args
        if len(args) != 1:
            continue
        body = _strip_docstring_body(list(stmt.body))
        if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
            continue
        if isinstance(body[0].value, ast.Name) and body[0].value.id == args[0].arg:
            names.add(stmt.name)
    return names


def _class_static_method_map(tree: ast.Module) -> Dict[Tuple[str, str], ast.FunctionDef]:
    out: Dict[Tuple[str, str], ast.FunctionDef] = {}
    for stmt in tree.body:
        if not isinstance(stmt, ast.ClassDef):
            continue
        for item in stmt.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            if any(
                (isinstance(d, ast.Name) and d.id == "staticmethod")
                or (isinstance(d, ast.Attribute) and d.attr == "staticmethod")
                for d in item.decorator_list
            ):
                out[(stmt.name, item.name)] = item
    return out


def _inline_class_static_delegation(func: ast.FunctionDef, statics: Dict[Tuple[str, str], ast.FunctionDef]) -> ast.FunctionDef:
    body = _strip_docstring_body(list(func.body))
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return func
    call = body[0].value
    if not isinstance(call, ast.Call):
        return func
    meth: Optional[str] = None
    cls: Optional[str] = None
    if isinstance(call.func, ast.Attribute):
        cls_node = call.func.value
        meth = call.func.attr
        if isinstance(cls_node, ast.Name):
            cls = cls_node.id
    if cls is None or meth is None:
        return func
    target = statics.get((cls, meth))
    if target is None:
        return func
    params = target.args.posonlyargs + target.args.args
    if len(call.args) != len(params):
        return func
    repl = {p.arg: a for p, a in zip(params, call.args)}
    inner_body = _preprocess_function_body(list(target.body))

    class _Rewriter(ast.NodeTransformer):
        def visit_Return(self, node: ast.Return) -> Any:
            if node.value is not None:
                node.value = _subst_names(node.value, repl)
            return node

    new_body = [_Rewriter().visit(s) for s in inner_body]
    return ast.copy_location(
        ast.FunctionDef(
            name=func.name,
            args=func.args,
            body=new_body,
            decorator_list=[],
            returns=func.returns,
        ),
        func,
    )


def _subst_names(node: ast.AST, repl: Dict[str, ast.expr]) -> ast.AST:
    class _Sub(ast.NodeTransformer):
        def visit_Name(self, n: ast.Name) -> Any:
            if n.id in repl:
                return repl[n.id]
            return n

    return _Sub().visit(node)


class _VarargForwarder(ast.NodeTransformer):
    """Rewrite ``args[i]`` loads to synthetic positional names in ``*args`` checkers."""

    def __init__(self, var: str) -> None:
        self.var = var

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        node = self.generic_visit(node)
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == self.var
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, int)
        ):
            return ast.Name(id=f"__arg{node.slice.value}", ctx=node.ctx)
        return node


def _vararg_index_span(body: List[ast.stmt], var: str) -> int:
    max_i = 1
    for stmt in body:
        for node in ast.walk(stmt):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == var
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, int)
            ):
                max_i = max(max_i, node.slice.value + 1)
    return max_i


def _normalize_vararg_entry(func: ast.FunctionDef) -> ast.FunctionDef:
    if func.args.vararg is None:
        return func
    var = func.args.vararg.arg
    span = _vararg_index_span(list(func.body), var)
    new_args = ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=f"__arg{i}") for i in range(span)],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[],
    )
    body = [_VarargForwarder(var).visit(s) for s in func.body]
    return ast.copy_location(
        ast.FunctionDef(
            name=func.name,
            args=new_args,
            body=body,
            decorator_list=func.decorator_list,
            returns=func.returns,
        ),
        func,
    )


def _flatten_checker_entry(
    func: ast.FunctionDef,
    tree: ast.Module,
    identity_decorators: Optional[Set[str]] = None,
) -> ast.FunctionDef:
    if not _is_checker_entry(func.name):
        return func
    ident_decos = identity_decorators if identity_decorators is not None else _identity_decorator_names(tree)
    deco = [d for d in func.decorator_list if not (isinstance(d, ast.Name) and d.id in ident_decos)]
    args = func.args
    if args.defaults:
        keep = len(args.args) - len(args.defaults)
        trimmed = args.args[:keep]
        args = ast.arguments(
            posonlyargs=args.posonlyargs,
            args=trimmed,
            vararg=args.vararg,
            kwonlyargs=args.kwonlyargs,
            kw_defaults=[],
            kwarg=args.kwarg,
            defaults=[],
        )
    elif args.kw_defaults:
        args = ast.arguments(
            posonlyargs=args.posonlyargs,
            args=args.args,
            vararg=args.vararg,
            kwonlyargs=args.kwonlyargs,
            kw_defaults=[],
            kwarg=args.kwarg,
            defaults=[],
        )
    func = ast.copy_location(
        ast.FunctionDef(
            name=func.name,
            args=args,
            body=func.body,
            decorator_list=deco,
            returns=func.returns,
        ),
        func,
    )
    statics = _class_static_method_map(tree)
    func = _inline_class_static_delegation(func, statics)
    func = _normalize_vararg_entry(func)
    return func


def _drop_orphan_classes(tree: ast.Module) -> ast.Module:
    used: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used.add(node.id)
    body = [
        stmt
        for stmt in tree.body
        if not (isinstance(stmt, ast.ClassDef) and stmt.name not in used)
    ]
    return ast.Module(body=body, type_ignores=tree.type_ignores)


def _flatten_module_for_skeleton(
    tree: ast.Module, identity_decorators: Optional[Set[str]] = None,
) -> ast.Module:
    new_body: List[ast.stmt] = []
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef):
            stmt = _flatten_checker_entry(stmt, tree, identity_decorators=identity_decorators)
            stmt = ast.copy_location(
                ast.FunctionDef(
                    name=stmt.name,
                    args=stmt.args,
                    body=_preprocess_function_body(list(stmt.body)),
                    decorator_list=stmt.decorator_list,
                    returns=stmt.returns,
                ),
                stmt,
            )
        new_body.append(stmt)
    tree = ast.Module(body=new_body, type_ignores=tree.type_ignores)
    tree = _drop_orphan_classes(_prune_uncalled_module_functions(tree))
    stripped = [
        s for s in tree.body if not isinstance(s, (ast.Import, ast.ImportFrom))
    ]
    return ast.Module(body=stripped, type_ignores=tree.type_ignores)


def _preprocess_skeleton_module(tree: ast.Module) -> ast.Module:
    helpers = _identity_helper_map(tree)
    lambdas = _module_lambda_identity_names(tree)
    new_body: List[ast.stmt] = []
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name in helpers:
            continue
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if stmt.targets[0].id in lambdas:
                continue
        new_body.append(stmt)
    tree = ast.Module(body=new_body, type_ignores=tree.type_ignores)
    return _inline_identity_call_tree(tree, helpers, lambdas)


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
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    sub = base_dir / node.module.replace(".", "/") / f"{alias.name}.py"
                    add_file(sub)
            elif node.level:
                parent = base_dir
                for _ in range(max(0, node.level - 1)):
                    parent = parent.parent
                if node.module:
                    add_file(parent / f"{node.module.replace('.', '/')}.py")
                    add_file(parent / node.module.replace(".", "/") / "__init__.py")
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if node.module:
                        add_file(parent / node.module.replace(".", "/") / f"{alias.name}.py")
                    else:
                        add_file(parent / f"{alias.name}.py")
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
    parsed = ast.parse(source, filename=str(source_path or "<checker>"))
    identity_decorators = _identity_decorator_names(parsed)
    tree = _prune_uncalled_module_functions(parsed)
    tree = _flatten_module_for_skeleton(tree, identity_decorators=identity_decorators)
    tree = _preprocess_skeleton_module(tree)
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
            if len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                left = self.visit(node.left)
                right = self.visit(node.comparators[0])
                lk, rk = _dump_key(left), _dump_key(right)
                if type(op) is ast.Eq and rk < lk:
                    left, right = right, left
                    return ast.Compare(left=left, ops=node.ops, comparators=[right])
                if type(op) is ast.Lt and rk < lk:
                    return ast.Compare(left=right, ops=[ast.Gt()], comparators=[left])
                if type(op) is ast.Gt and rk < lk:
                    return ast.Compare(left=right, ops=[ast.Lt()], comparators=[left])
                if type(op) is ast.Gt and isinstance(left, ast.Constant):
                    return ast.Compare(left=right, ops=[ast.Lt()], comparators=[left])
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
    module_stmts = tree.body if isinstance(tree, ast.Module) else []
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
            stmts = module_stmts + _function_enclosing_stmts(tree, node)
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


def _floaty_bindings(tree: ast.AST) -> Dict[str, str]:
    """Map local names to floaty module roots (math, cmath, statistics, numpy)."""
    binds: Dict[str, str] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for stmt in body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                root = alias.name.split(".", 1)[0]
                if root in FLOATY_MODULE_ROOTS:
                    binds[alias.asname or root] = root
        elif isinstance(stmt, ast.ImportFrom) and stmt.module:
            root = stmt.module.split(".", 1)[0]
            if root not in FLOATY_MODULE_ROOTS:
                continue
            for alias in stmt.names:
                local = alias.asname or alias.name
                if root == "numpy":
                    binds[local] = "numpy"
                    continue
                if root in ("cmath", "statistics"):
                    binds[local] = root
                    continue
                if alias.name == "*":
                    binds["*"] = "math"
                    continue
                if alias.name not in MATH_INT_ONLY_ATTRS:
                    binds[local] = f"math:attr:{alias.name}"
                else:
                    binds[local] = f"math:safe:{alias.name}"
    return binds


def _is_negative_pow_exponent(expr: ast.expr) -> bool:
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
        return True
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, float)) and expr.value < 0:
        return True
    return False


def _collect_math_numpy_findings(tree: ast.AST) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    binds = _floaty_bindings(tree)
    seen: Set[Tuple[int, str]] = set()

    def add(rule: str, line: int, detail: str) -> None:
        key = (line, rule)
        if key not in seen:
            seen.add(key)
            out.append({"rule": rule, "line": line, "detail": detail})

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root == "numpy":
                    add(
                        "NUMPY_IN_EXACT_CHECKER",
                        node.lineno,
                        "numpy is float-oriented; avoid in exact certificate checkers.",
                    )
                elif root == "cmath":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        "cmath is float-oriented; avoid in exact certificate checkers.",
                    )
                elif root == "statistics":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        "statistics is float-oriented; avoid in exact certificate checkers.",
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root == "numpy":
                add(
                    "NUMPY_IN_EXACT_CHECKER",
                    node.lineno,
                    "numpy is float-oriented; avoid in exact certificate checkers.",
                )
            elif root == "cmath":
                add(
                    "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                    node.lineno,
                    "cmath is float-oriented; avoid in exact certificate checkers.",
                )
            elif root == "statistics":
                add(
                    "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                    node.lineno,
                    "statistics is float-oriented; avoid in exact certificate checkers.",
                )
            elif node.module == "math":
                for alias in node.names:
                    name = alias.name
                    if name == "*":
                        add(
                            "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            node.lineno,
                            "from math import * pulls in float routines; use int-only math attrs.",
                        )
                    elif name not in MATH_INT_ONLY_ATTRS:
                        add(
                            "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            node.lineno,
                            f"math.{name} may produce floats; int-only allowlist applies.",
                        )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                attr = node.func.attr
                root = binds.get(mod, mod)
                if root == "numpy" or mod in ("np", "numpy"):
                    add("NUMPY_IN_EXACT_CHECKER", node.lineno, "numpy call in exact checker.")
                elif root == "cmath":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        f"cmath.{attr} is float-oriented.",
                    )
                elif root == "statistics":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        f"statistics.{attr} is float-oriented.",
                    )
                elif root == "math" and attr not in MATH_INT_ONLY_ATTRS:
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        f"math.{attr} may produce floats; int-only allowlist applies.",
                    )
            elif isinstance(node.func, ast.Name):
                bound = binds.get(node.func.id)
                if bound == "numpy":
                    add("NUMPY_IN_EXACT_CHECKER", node.lineno, "numpy call in exact checker.")
                elif bound == "cmath":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        "cmath call via import alias in exact checker.",
                    )
                elif bound == "statistics":
                    add(
                        "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                        node.lineno,
                        "statistics call via import alias in exact checker.",
                    )
                elif bound and bound.startswith("math:attr:"):
                    attr = bound.split(":", 2)[2]
                    if attr not in MATH_INT_ONLY_ATTRS:
                        add(
                            "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            node.lineno,
                            f"math.{attr} via import alias may produce floats.",
                        )
                elif node.func.id == "pow" and len(node.args) >= 2:
                    exp = node.args[1]
                    if _is_negative_pow_exponent(exp):
                        add(
                            "FLOAT_NEGATIVE_EXPONENT",
                            node.lineno,
                            "pow() with negative exponent often produces float; use exact rationals.",
                        )
                    elif not isinstance(exp, ast.Constant):
                        add(
                            "FLOAT_NON_LITERAL_EXPONENT",
                            node.lineno,
                            "pow() exponent is not a literal; may yield float in exact checkers.",
                        )
    return out


def _collect_indirect_float_hazards(tree: ast.AST) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    binds = _floaty_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                mod = node.args[0]
                attr = node.args[1]
                mod_name = mod.id if isinstance(mod, ast.Name) else None
                root = binds.get(mod_name, mod_name) if mod_name else None
                if root in ("math", "cmath", "statistics") and isinstance(attr, ast.Constant):
                    aname = str(attr.value)
                    if root == "math" and aname not in MATH_INT_ONLY_ATTRS:
                        out.append({
                            "rule": "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            "line": node.lineno,
                            "detail": f"getattr({root!r}, {aname!r}) may yield float.",
                        })
                    elif root in ("cmath", "statistics"):
                        out.append({
                            "rule": "FLOAT_MATH_CALL_IN_EXACT_CHECKER",
                            "line": node.lineno,
                            "detail": f"getattr({root!r}, ...) is float-oriented.",
                        })
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "operator" and node.func.attr in ("truediv", "itruediv"):
                    out.append({
                        "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": f"operator.{node.func.attr} produces float division.",
                    })
            if isinstance(node.func, ast.Attribute) and node.func.attr == "__truediv__":
                out.append({
                    "rule": "FLOAT_DIVISION_IN_EXACT_CHECKER",
                    "line": node.lineno,
                    "detail": "Calling __truediv__ is true float division.",
                })
            if isinstance(node.func, ast.Name):
                if node.func.id in ("divmod", "round"):
                    out.append({
                        "rule": "FLOAT_CALL_IN_EXACT_CHECKER",
                        "line": node.lineno,
                        "detail": f"{node.func.id}() can introduce float arithmetic.",
                    })
    return out


def _parse_source_tree(source: str, label: str) -> Tuple[Optional[ast.AST], Optional[Dict[str, Any]]]:
    try:
        return ast.parse(source, filename=label), None
    except SyntaxError as exc:
        line = exc.lineno or 0
        detail = exc.msg or "syntax error"
        return None, {
            "label": label,
            "verdict": VERDICT_FAIL,
            "clean": False,
            "alpha_skeleton_sha256": "",
            "findings_count": 1,
            "findings": [{"rule": "SYNTAX_ERROR", "line": line, "detail": detail}],
            "syntax_error": {
                "line": line,
                "offset": exc.offset,
                "msg": detail,
                "text": exc.text,
            },
        }


def _first_local_import_line(tree: ast.Module, base_dir: Path) -> int:
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if _resolve_local_module_paths(ast.Module(body=[node], type_ignores=[]), base_dir):
                return getattr(node, "lineno", 1) or 1
    return 1


def _collect_dynamic_import_findings(tree: ast.AST) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            out.append({
                "rule": "DYNAMIC_IMPORT_IN_CHECKER",
                "line": node.lineno,
                "detail": "Dynamic __import__() breaks static dual-checker copy lint.",
            })
        if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
            val = node.func.value
            if isinstance(val, ast.Name) and val.id == "importlib":
                out.append({
                    "rule": "DYNAMIC_IMPORT_IN_CHECKER",
                    "line": node.lineno,
                    "detail": "importlib.import_module() breaks static dual-checker copy lint.",
                })
    return out


def audit_checker_source(source: str, label: str = "<checker>", strict_exact_math: bool = True) -> Dict[str, Any]:
    tree, err = _parse_source_tree(source, label)
    if err is not None:
        return err
    assert tree is not None
    findings: List[Dict[str, Any]] = []

    findings.extend(_collect_dynamic_import_findings(tree))
    if strict_exact_math:
        findings.extend(_collect_float_division_findings(tree))
        findings.extend(_collect_math_numpy_findings(tree))
        findings.extend(_collect_indirect_float_hazards(tree))

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
                elif isinstance(node.right, ast.Constant) and not isinstance(node.right.value, int):
                    findings.append({
                        "rule": "FLOAT_NON_LITERAL_EXPONENT",
                        "line": node.lineno,
                        "detail": "Non-integer ** exponent may yield float (e.g. ** 0.5).",
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
    spec_label = str(spec_path) if spec_path is not None else "spec"
    impl_label = str(impl_path) if impl_path is not None else "impl"
    s_tree, s_err = _parse_source_tree(spec_source, spec_label)
    if s_err is not None:
        return {**s_err, "verdict": VERDICT_FAIL, "distinct_alpha_skeleton": False}
    i_tree, i_err = _parse_source_tree(impl_source, impl_label)
    if i_err is not None:
        return {**i_err, "verdict": VERDICT_FAIL, "distinct_alpha_skeleton": False}
    s_rep = audit_checker_source(spec_source, label=spec_label, strict_exact_math=strict_exact_math)
    i_rep = audit_checker_source(impl_source, label=impl_label, strict_exact_math=strict_exact_math)
    s_skel = alpha_skeleton_sha256(spec_source, preserved_api=preserved_api, source_path=spec_path)
    i_skel = alpha_skeleton_sha256(impl_source, preserved_api=preserved_api, source_path=impl_path)
    distinct = s_skel != i_skel
    shared_local: List[str] = []
    dual_findings: List[Dict[str, Any]] = []
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
        spec_del = bool(spec_locals)
        impl_del = bool(impl_locals)
        if spec_del != impl_del:
            distinct = False
            mismatch_line = 1
            if spec_del and spec_path is not None:
                mismatch_line = _first_local_import_line(
                    ast.parse(spec_source, filename=str(spec_path)),
                    spec_path.resolve().parent,
                )
            elif impl_del and impl_path is not None:
                mismatch_line = _first_local_import_line(
                    ast.parse(impl_source, filename=str(impl_path)),
                    impl_path.resolve().parent,
                )
            dual_findings.append({
                "rule": "LOCAL_MODULE_DELEGATION_MISMATCH",
                "line": mismatch_line,
                "detail": (
                    "One checker delegates to a local module while the other inlines logic; "
                    "dual mode cannot treat them as independent."
                ),
            })
    for label, src in (("spec", spec_source), ("impl", impl_source)):
        for f in _collect_dynamic_import_findings(ast.parse(src, filename=label)):
            distinct = False
            dual_findings.append({**f, "detail": f"{f['detail']} ({label})"})
    clean = s_rep["clean"] and i_rep["clean"]
    verdict = (
        VERDICT_DISTINCT_LINT_CLEAN
        if (distinct and clean and not dual_findings)
        else VERDICT_FAIL
    )
    return {
        "verdict": verdict,
        "distinct_alpha_skeleton": distinct,
        "shared_local_modules": shared_local,
        "dual_findings": dual_findings,
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

    def emit(res: Dict[str, Any]) -> int:
        if args.json:
            print(json.dumps(res, indent=2))
        return 0 if res.get("verdict") == VERDICT_DISTINCT_LINT_CLEAN or res.get("clean") else 1

    if args.dual is not None:
        spec_path, impl_path = args.dual
        try:
            spec_src = spec_path.read_text(encoding="utf-8")
            impl_src = impl_path.read_text(encoding="utf-8")
        except OSError as e:
            err = {
                "verdict": VERDICT_FAIL,
                "clean": False,
                "findings": [{"rule": "READ_ERROR", "line": 0, "detail": str(e)}],
            }
            if args.json:
                print(json.dumps(err, indent=2))
            return 1
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
    try:
        spec_src = single.read_text(encoding="utf-8")
    except OSError as e:
        err = {
            "verdict": VERDICT_FAIL,
            "clean": False,
            "findings": [{"rule": "READ_ERROR", "line": 0, "detail": str(e)}],
        }
        if args.json:
            print(json.dumps(err, indent=2))
        return 1

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
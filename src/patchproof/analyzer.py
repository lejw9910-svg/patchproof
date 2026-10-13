"""Small, advisory AST checks for Python vulnerability lab source.

Findings identify patterns worth reviewing, not proof of exploitability. This is
not a security audit or a full data-flow analyzer: aliases assigned at runtime,
branch-dependent values, interprocedural flows, and custom wrappers can evade
checks. SQL checks recognize method names, so non-SQL ``execute`` methods may
produce false positives. Variable tracking follows source order within scopes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule_id: str
    cwe: str
    line: int
    message: str
    severity: str = "warning"


class _Analyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.aliases: list[dict[str, str | None]] = [{}]
        self.dynamic: list[dict[str, bool]] = [{}]

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            for scope in reversed(self.aliases):
                if node.id in scope:
                    return scope[node.id]
            return node.id if node.id in {"eval", "exec"} else None
        if isinstance(node, ast.Attribute):
            parent = self._resolve(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    def _dynamic_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            for scope in reversed(self.dynamic):
                if node.id in scope:
                    return scope[node.id]
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(value, ast.FormattedValue) for value in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            # Concatenated literals contain no interpolation.
            return not self._literal_string(node)
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        )

    def _literal_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        return (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Add)
            and self._literal_string(node.left)
            and self._literal_string(node.right)
        )

    def _bind(self, target: ast.AST, dynamic: bool = False) -> None:
        if isinstance(target, ast.Name):
            self.aliases[-1][target.id] = None
            self.dynamic[-1][target.id] = dynamic
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item)

    def _add(self, node: ast.Call, rule: str, cwe: str, message: str) -> None:
        self.findings.append(Finding(rule, cwe, node.lineno, message))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.aliases[-1][name] = alias.name if alias.asname else name
            self.dynamic[-1][name] = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                name = alias.asname or alias.name
                self.aliases[-1][name] = (
                    f"{node.module}.{alias.name}" if node.module and not node.level else None
                )
                self.dynamic[-1][name] = False

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        dynamic = self._dynamic_string(node.value)
        for target in node.targets:
            self.visit(target)
            self._bind(target, dynamic)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, self._dynamic_string(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        dynamic = self._dynamic_string(node.target) or isinstance(node.op, (ast.Add, ast.Mod))
        self._bind(node.target, dynamic)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Defaults and decorators run in the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self._bind(ast.Name(id=node.name))
        self.aliases.append({})
        self.dynamic.append({})
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg:
            arguments.append(node.args.vararg)
        if node.args.kwarg:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            self._bind(ast.Name(id=argument.arg))
        for statement in node.body:
            self.visit(statement)
        self.dynamic.pop()
        self.aliases.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind(ast.Name(id=node.name))
        self.aliases.append({})
        self.dynamic.append({})
        for statement in node.body:
            self.visit(statement)
        self.dynamic.pop()
        self.aliases.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(node.func)
        if name in {"pickle.load", "pickle.loads"}:
            self._add(node, "PP001", "CWE-502", "Pickle deserialization requires trusted input.")
        elif name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self._add(node, "PP002", "CWE-95", "Dynamic Python execution requires trusted input.")
        elif name in {"yaml.load", "yaml.unsafe_load"}:
            loader = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "Loader":
                    loader = keyword.value
            safe = loader is not None and self._resolve(loader) in {"yaml.SafeLoader", "yaml.CSafeLoader"}
            if name == "yaml.unsafe_load" or not safe:
                self._add(node, "PP003", "CWE-502", "YAML loading without a known safe loader requires review.")

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"}:
            query = node.args[0] if node.args else None
            if query is None:
                query = next((kw.value for kw in node.keywords if kw.arg in {"sql", "query", "operation"}), None)
            if query is not None and self._dynamic_string(query):
                self._add(node, "PP004", "CWE-89", "Dynamically constructed SQL-like statement; review parameter binding.")
        self.generic_visit(node)


def analyze_file(path: Path) -> list[Finding]:
    """Return deterministic advisory findings; decoding and syntax errors propagate."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=str(path))
    analyzer = _Analyzer()
    analyzer.visit(tree)
    return sorted(analyzer.findings, key=lambda finding: (finding.line, finding.rule_id, finding.message))

"""
Codebase Architecture Parser

Walks a target codebase, extracts structural metadata (routes, schemas, models,
dependencies), and builds a GlobalContext object that the Shadow Audit Agent
uses for adversarial spec generation.

Usage (CLI):
    python -m src.context.parser --init --path ./target-codebase
"""
import ast
import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field, asdict

import typer

logger = logging.getLogger(__name__)
cli = typer.Typer()


@dataclass
class EndpointSchema:
    path: str
    method: str
    handler: str
    module: str
    parameters: list[str] = field(default_factory=list)
    return_type: str = "Any"


@dataclass
class GlobalContext:
    """Serialisable snapshot of the codebase's architectural context."""
    project_id: str
    endpoints: list[EndpointSchema] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    checksum: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContextParser:
    """
    Scans Python source files in a directory and extracts:
    - FastAPI route definitions
    - Pydantic model class names
    - Installed dependency versions (from requirements.txt)
    """

    def parse(self, root_path: str, project_id: str = "unknown") -> GlobalContext:
        root = Path(root_path)
        ctx = GlobalContext(project_id=project_id)

        for py_file in root.rglob("*.py"):
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
                self._extract_from_tree(tree, str(py_file), ctx)
            except (SyntaxError, OSError) as exc:
                logger.warning("Skipping %s: %s", py_file, exc)

        # Parse requirements
        req_file = root / "requirements.txt"
        if req_file.exists():
            ctx.dependencies = self._parse_requirements(req_file)

        # Stable checksum for cache invalidation
        payload = json.dumps(ctx.to_dict(), sort_keys=True).encode()
        ctx.checksum = hashlib.sha256(payload).hexdigest()[:12]

        logger.info(
            "Parsed %s: %d endpoints, %d models, %d deps",
            root_path, len(ctx.endpoints), len(ctx.models), len(ctx.dependencies),
        )
        return ctx

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _extract_from_tree(self, tree: ast.AST, filepath: str, ctx: GlobalContext) -> None:
        for node in ast.walk(tree):
            # Detect FastAPI route decorators on both sync and async functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    endpoint = self._try_parse_route_decorator(decorator, node, filepath)
                    if endpoint:
                        ctx.endpoints.append(endpoint)

            # Detect Pydantic / SQLAlchemy model classes
            if isinstance(node, ast.ClassDef):
                bases = [self._name_of(b) for b in node.bases]
                if any(b in ("BaseModel", "Base", "DeclarativeBase") for b in bases):
                    ctx.models.append(node.name)

    def _try_parse_route_decorator(
        self, decorator: ast.expr, func: ast.FunctionDef | ast.AsyncFunctionDef, filepath: str
    ) -> EndpointSchema | None:
        http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
        if not isinstance(decorator, ast.Call):
            return None
        func_node = decorator.func
        # Support both `@app.get(...)` and `@router.post(...)`
        if isinstance(func_node, ast.Attribute) and func_node.attr in http_methods:
            path = ""
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                path = decorator.args[0].value
            params = [a.arg for a in func.args.args if a.arg != "self"]
            return EndpointSchema(
                path=path,
                method=func_node.attr.upper(),
                handler=func.name,
                module=filepath,
                parameters=params,
            )
        return None

    @staticmethod
    def _name_of(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _parse_requirements(req_file: Path) -> dict[str, str]:
        deps: dict[str, str] = {}
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                deps[name.strip()] = version.strip()
            else:
                deps[line] = "unpinned"
        return deps


# ------------------------------------------------------------------ #
# CLI entry point                                                       #
# ------------------------------------------------------------------ #

@cli.command()
def main(
    path: str = typer.Option(".", help="Root path of the target codebase"),
    project_id: str = typer.Option("my-project", help="Project identifier"),
    init: bool = typer.Option(False, "--init", help="Index into vector store after parsing"),
    output: str = typer.Option("", help="Optional JSON file to write context to"),
):
    """Parse a codebase and build the global architectural context."""
    parser = ContextParser()
    ctx = parser.parse(path, project_id=project_id)

    if output:
        Path(output).write_text(json.dumps(ctx.to_dict(), indent=2))
        typer.echo(f"Context written to {output}")
    else:
        typer.echo(json.dumps(ctx.to_dict(), indent=2))

    if init:
        typer.echo("[init] Vector store indexing not available in demo mode — set OPENSEARCH_ENDPOINT.")


if __name__ == "__main__":
    cli()

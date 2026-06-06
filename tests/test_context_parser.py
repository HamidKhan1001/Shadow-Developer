"""
Tests for the ContextParser — verifies codebase AST extraction.
"""
import textwrap
import tempfile
import os
from pathlib import Path

import pytest

from src.context.parser import ContextParser


@pytest.fixture
def sample_fastapi_code() -> str:
    return textwrap.dedent("""
        from fastapi import APIRouter
        from pydantic import BaseModel

        router = APIRouter()

        class ItemCreate(BaseModel):
            name: str
            price: float

        @router.post("/items")
        async def create_item(body: ItemCreate):
            return body

        @router.get("/items/{item_id}")
        async def get_item(item_id: int):
            return {"id": item_id}
    """)


@pytest.fixture
def temp_project(sample_fastapi_code: str, tmp_path: Path) -> Path:
    (tmp_path / "routes.py").write_text(sample_fastapi_code)
    (tmp_path / "requirements.txt").write_text("fastapi==0.111.0\npydantic==2.7.1\n")
    return tmp_path


class TestContextParser:
    def test_extracts_endpoints(self, context_parser: ContextParser, temp_project: Path):
        ctx = context_parser.parse(str(temp_project), project_id="test")
        paths = [e.path for e in ctx.endpoints]
        assert "/items" in paths
        assert "/items/{item_id}" in paths

    def test_extracts_http_methods(self, context_parser: ContextParser, temp_project: Path):
        ctx = context_parser.parse(str(temp_project), project_id="test")
        methods = {e.method for e in ctx.endpoints}
        assert "POST" in methods
        assert "GET" in methods

    def test_extracts_models(self, context_parser: ContextParser, temp_project: Path):
        ctx = context_parser.parse(str(temp_project), project_id="test")
        assert "ItemCreate" in ctx.models

    def test_extracts_dependencies(self, context_parser: ContextParser, temp_project: Path):
        ctx = context_parser.parse(str(temp_project), project_id="test")
        assert ctx.dependencies.get("fastapi") == "0.111.0"
        assert ctx.dependencies.get("pydantic") == "2.7.1"

    def test_checksum_is_stable(self, context_parser: ContextParser, temp_project: Path):
        ctx1 = context_parser.parse(str(temp_project), project_id="test")
        ctx2 = context_parser.parse(str(temp_project), project_id="test")
        assert ctx1.checksum == ctx2.checksum

    def test_checksum_changes_on_code_change(self, context_parser: ContextParser, temp_project: Path):
        ctx1 = context_parser.parse(str(temp_project), project_id="test")
        # Add a new route
        (temp_project / "routes.py").write_text(
            (temp_project / "routes.py").read_text() + "\n@router.delete('/items/{item_id}')\nasync def delete_item(item_id: int): pass\n"
        )
        ctx2 = context_parser.parse(str(temp_project), project_id="test")
        assert ctx1.checksum != ctx2.checksum

    def test_skips_files_with_syntax_errors(self, context_parser: ContextParser, tmp_path: Path):
        (tmp_path / "broken.py").write_text("def broken syntax((:")
        (tmp_path / "valid.py").write_text("x = 1\n")
        # Should not raise
        ctx = context_parser.parse(str(tmp_path), project_id="test")
        assert ctx is not None

    def test_empty_directory(self, context_parser: ContextParser, tmp_path: Path):
        ctx = context_parser.parse(str(tmp_path), project_id="empty")
        assert ctx.endpoints == []
        assert ctx.models == []
        assert ctx.dependencies == {}

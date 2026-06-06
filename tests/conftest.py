"""
Shared pytest fixtures for Shadow Developer test suite.
"""
import pytest
from fastapi.testclient import TestClient

from src.interceptor.main import app
from src.context.parser import ContextParser, GlobalContext, EndpointSchema
from src.auditor.engine import AuditEngine, _build_demo_context


@pytest.fixture(scope="session")
def client():
    """FastAPI test client, reused across the session."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def demo_context() -> GlobalContext:
    """Pre-built demo GlobalContext with seeded endpoints and models."""
    return _build_demo_context()


@pytest.fixture
def audit_engine() -> AuditEngine:
    """Fresh AuditEngine instance for each test."""
    return AuditEngine()


@pytest.fixture
def context_parser() -> ContextParser:
    return ContextParser()

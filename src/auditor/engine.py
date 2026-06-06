"""
Audit Engine — the heart of Shadow Developer.

Orchestrates the full 4-step pipeline:
  1. Pull global context (from vector store or in-memory demo data)
  2. Run security rules against the incoming prompt
  3. Run architectural drift rules against the codebase context
  4. Reconcile, score, and return an AuditResult
"""
import logging
import textwrap
from typing import Any

from ..interceptor.models import AuditResult, AuditStatus, ConflictDetail
from ..context.parser import ContextParser, GlobalContext
from ..context.vector_store import InMemoryVectorStore
from .rules.security import SECURITY_RULES
from .rules.architecture import check_api_drift, check_schema_collision, check_dependency_conflict

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Demo / seed data                                                     #
# ------------------------------------------------------------------ #

DEMO_CONTEXT_SEED = {
    "project_id": "ecommerce-platform-v2",
    "endpoints": [
        {"path": "/payments/charge", "method": "POST", "handler": "charge_card", "module": "payments/routes.py", "parameters": ["body", "current_user"]},
        {"path": "/users/me", "method": "GET", "handler": "get_current_user", "module": "users/routes.py", "parameters": ["current_user"]},
        {"path": "/orders", "method": "GET", "handler": "list_orders", "module": "orders/routes.py", "parameters": ["current_user", "page", "limit"]},
        {"path": "/orders", "method": "POST", "handler": "create_order", "module": "orders/routes.py", "parameters": ["body", "current_user"]},
    ],
    "models": ["User", "Order", "PaymentIntent", "Subscription"],
    "dependencies": {
        "fastapi": "0.111.0",
        "sqlalchemy": "2.0.30",
        "stripe": "9.4.0",
        "pydantic": "2.7.1",
    },
}


def _build_demo_context() -> GlobalContext:
    """Builds a pre-seeded GlobalContext for local demo & testing."""
    from ..context.parser import EndpointSchema
    ctx = GlobalContext(project_id=DEMO_CONTEXT_SEED["project_id"])
    for ep in DEMO_CONTEXT_SEED["endpoints"]:
        ctx.endpoints.append(EndpointSchema(**ep))
    ctx.models = DEMO_CONTEXT_SEED["models"]
    ctx.dependencies = DEMO_CONTEXT_SEED["dependencies"]
    return ctx


# ------------------------------------------------------------------ #
# Recommended test generation                                          #
# ------------------------------------------------------------------ #

def _generate_test_suggestions(prompt: str, conflicts: list[ConflictDetail]) -> list[str]:
    """Produce a list of test descriptions based on the prompt and conflicts found."""
    suggestions = [
        "Integration test: verify the new endpoint returns 401 for unauthenticated requests",
        "Integration test: ensure idempotency — calling the endpoint twice with the same payload produces the same result",
    ]
    for c in conflicts:
        if c.category == "security":
            suggestions.append(f"Security test: validate that {c.affected_component} rejects malformed / injected payloads")
        elif c.category == "api_drift":
            suggestions.append(f"Regression test: existing {c.affected_component} contract still returns expected schema")
        elif c.category == "schema_collision":
            suggestions.append(f"Migration test: Alembic upgrade/downgrade on {c.affected_component} leaves no data loss")
    return list(dict.fromkeys(suggestions))  # deduplicate while preserving order


# ------------------------------------------------------------------ #
# Main Engine                                                          #
# ------------------------------------------------------------------ #

class AuditEngine:
    """
    Stateful engine that holds a cache of recent audit results and an
    in-memory context store for demo mode.
    """

    def __init__(self) -> None:
        self._cache: dict[str, AuditResult] = {}
        self._vector_store = InMemoryVectorStore()
        self._context_parser = ContextParser()
        self._demo_ctx = _build_demo_context()

        # Seed vector store with demo architectural docs
        self._seed_vector_store()

    def _seed_vector_store(self) -> None:
        self._vector_store.index(
            "arch-overview",
            "The ecommerce-platform-v2 uses FastAPI, SQLAlchemy ORM, Stripe for payments, "
            "and JWT-based authentication. All payment endpoints require HMAC signature verification "
            "for webhooks. The User, Order, PaymentIntent, and Subscription models are in the core schema.",
            metadata={"type": "architecture"},
        )
        self._vector_store.index(
            "security-policy",
            "All endpoints must implement rate limiting. Webhook routes must validate Stripe signatures. "
            "No raw SQL is allowed; use SQLAlchemy ORM. All admin routes require role-based access control.",
            metadata={"type": "policy"},
        )

    async def run(
        self,
        audit_id: str,
        prompt: str,
        project_id: str,
        author: str,
        branch: str,
    ) -> AuditResult:
        """Execute the full Shadow Audit pipeline and return a result."""
        logger.info("Audit pipeline start | id=%s", audit_id)

        # Step 1 — Retrieve relevant context from vector store
        related_docs = self._vector_store.search(prompt, top_k=3)
        logger.debug("Retrieved %d context docs", len(related_docs))

        # Step 2 — Use demo context (real systems would build this per project_id)
        ctx = self._demo_ctx

        # Step 3 — Run security rules
        conflicts: list[ConflictDetail] = []
        for rule in SECURITY_RULES:
            conflicts.extend(rule(prompt))

        # Step 4 — Run architectural rules
        conflicts.extend(check_api_drift(prompt, ctx))
        conflicts.extend(check_schema_collision(prompt, ctx))
        conflicts.extend(check_dependency_conflict(prompt, ctx))

        # Step 5 — Reconcile and decide status
        critical_count = sum(1 for c in conflicts if c.severity == "critical")
        high_count = sum(1 for c in conflicts if c.severity == "high")

        if critical_count > 0:
            status = AuditStatus.FAILED
            message = (
                f"Audit FAILED — {critical_count} critical issue(s) detected. "
                "Resolve all critical conflicts before proceeding."
            )
        elif high_count > 0:
            status = AuditStatus.NEEDS_REVISION
            message = (
                f"Audit requires revision — {high_count} high-severity issue(s) found. "
                "Address before merging to production."
            )
        elif conflicts:
            status = AuditStatus.PASSED
            message = "Audit passed with warnings. Review medium/low issues."
        else:
            status = AuditStatus.PASSED
            message = "Audit passed — no conflicts detected. Safe to proceed."

        tests = _generate_test_suggestions(prompt, conflicts)

        result = AuditResult(
            audit_id=audit_id,
            project_id=project_id,
            status=status,
            prompt_summary=textwrap.shorten(prompt, width=120),
            conflicts=conflicts,
            auto_remediation_applied=False,
            recommended_tests=tests,
            message=message,
        )
        self._cache[audit_id] = result
        logger.info("Audit complete | id=%s status=%s conflicts=%d", audit_id, status, len(conflicts))
        return result

    def get_cached(self, audit_id: str) -> AuditResult | None:
        return self._cache.get(audit_id)

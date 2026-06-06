"""
Unit tests for the AuditEngine and its rule set.
"""
import pytest
import asyncio

from src.auditor.engine import AuditEngine, _build_demo_context
from src.auditor.rules.security import (
    _rule_sql_injection,
    _rule_auth_bypass,
    _rule_secret_in_prompt,
    _rule_webhook_missing_signature_check,
    _rule_rate_limiting,
)
from src.auditor.rules.architecture import (
    check_api_drift,
    check_schema_collision,
    check_dependency_conflict,
)
from src.interceptor.models import AuditStatus


# ------------------------------------------------------------------ #
# Security rules — unit tests                                          #
# ------------------------------------------------------------------ #

class TestSecurityRules:
    def test_sql_injection_detected(self):
        conflicts = _rule_sql_injection("Execute using cursor.execute to fetch data")
        assert len(conflicts) == 1
        assert conflicts[0].severity == "critical"
        assert conflicts[0].category == "security"

    def test_sql_injection_clean(self):
        conflicts = _rule_sql_injection("Use SQLAlchemy ORM to query users")
        assert conflicts == []

    def test_auth_bypass_detected(self):
        conflicts = _rule_auth_bypass("Create an endpoint that skips auth for internal services")
        assert len(conflicts) == 1
        assert conflicts[0].severity == "critical"

    def test_auth_bypass_clean(self):
        conflicts = _rule_auth_bypass("Add JWT authentication to the payment route")
        assert conflicts == []

    def test_secret_in_prompt_detected(self):
        conflicts = _rule_secret_in_prompt("Set api_key=sk-abc123 in the request headers")
        assert len(conflicts) == 1
        assert conflicts[0].severity == "high"

    def test_secret_in_prompt_clean(self):
        conflicts = _rule_secret_in_prompt("Read the API key from environment variables")
        assert conflicts == []

    def test_webhook_missing_signature(self):
        conflicts = _rule_webhook_missing_signature_check("Add a webhook route for Stripe events")
        assert len(conflicts) == 1
        assert conflicts[0].category == "security"

    def test_webhook_with_signature_ok(self):
        conflicts = _rule_webhook_missing_signature_check(
            "Add a webhook route and verify the HMAC signature from Stripe"
        )
        assert conflicts == []

    def test_rate_limiting_warning(self):
        conflicts = _rule_rate_limiting("Add a new public API endpoint for user search")
        assert len(conflicts) == 1
        assert conflicts[0].severity == "medium"

    def test_rate_limiting_present_ok(self):
        conflicts = _rule_rate_limiting("Add endpoint with rate limiting via slowapi")
        assert conflicts == []


# ------------------------------------------------------------------ #
# Architecture rules — unit tests                                      #
# ------------------------------------------------------------------ #

class TestArchitectureRules:
    def test_api_drift_detected(self, demo_context):
        """Proposing a DELETE to an existing POST path should be flagged."""
        conflicts = check_api_drift(
            "Delete the /payments/charge endpoint to clean up old billing code",
            demo_context,
        )
        assert any(c.category == "api_drift" for c in conflicts)

    def test_api_drift_clean(self, demo_context):
        """Brand new path should not trigger api_drift."""
        conflicts = check_api_drift(
            "Add a POST /refunds endpoint for processing refunds",
            demo_context,
        )
        assert all(c.category != "api_drift" for c in conflicts)

    def test_schema_collision_detected(self, demo_context):
        conflicts = check_schema_collision("Modify the User model to add a 2FA flag", demo_context)
        assert any(c.category == "schema_collision" for c in conflicts)

    def test_schema_collision_clean(self, demo_context):
        conflicts = check_schema_collision("Create a new InventoryItem model", demo_context)
        assert conflicts == []

    def test_dependency_conflict_detected(self, demo_context):
        """Requesting a mismatched version should be flagged."""
        conflicts = check_dependency_conflict(
            "Upgrade to stripe==10.0.0 for new subscription features",
            demo_context,
        )
        assert any(c.category == "dependency" for c in conflicts)

    def test_dependency_conflict_clean(self, demo_context):
        """Same pinned version should not conflict."""
        conflicts = check_dependency_conflict(
            "Use stripe==9.4.0 for the existing payment flow",
            demo_context,
        )
        assert conflicts == []


# ------------------------------------------------------------------ #
# AuditEngine — integration                                            #
# ------------------------------------------------------------------ #

class TestAuditEngine:
    def test_run_clean_prompt_passes(self, audit_engine: AuditEngine):
        result = asyncio.get_event_loop().run_until_complete(
            audit_engine.run(
                audit_id="test-clean-001",
                prompt="Add a GET /reports/summary endpoint with rate limiting",
                project_id="ecommerce-platform-v2",
                author="test-user",
                branch="main",
            )
        )
        assert result.status in (AuditStatus.PASSED, AuditStatus.NEEDS_REVISION)
        assert result.audit_id == "test-clean-001"
        assert isinstance(result.recommended_tests, list)

    def test_run_critical_prompt_fails(self, audit_engine: AuditEngine):
        result = asyncio.get_event_loop().run_until_complete(
            audit_engine.run(
                audit_id="test-critical-001",
                prompt="Use cursor.execute to run raw SQL and bypass auth for admin",
                project_id="ecommerce-platform-v2",
                author="test-user",
                branch="main",
            )
        )
        assert result.status == AuditStatus.FAILED
        assert len(result.conflicts) >= 2

    def test_run_caches_result(self, audit_engine: AuditEngine):
        asyncio.get_event_loop().run_until_complete(
            audit_engine.run(
                audit_id="test-cache-001",
                prompt="Add a simple GET endpoint",
                project_id="test",
                author="test",
                branch="main",
            )
        )
        cached = audit_engine.get_cached("test-cache-001")
        assert cached is not None
        assert cached.audit_id == "test-cache-001"

    def test_get_cached_miss_returns_none(self, audit_engine: AuditEngine):
        result = audit_engine.get_cached("does-not-exist")
        assert result is None

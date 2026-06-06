"""
Pydantic models for the Interceptor API layer.
"""
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class AuditStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_REVISION = "needs_revision"


class PromptInterceptRequest(BaseModel):
    """Incoming developer prompt to be audited before code generation."""
    prompt: str = Field(..., description="The developer's natural language feature prompt")
    project_id: str = Field(..., description="Unique identifier for the target project")
    author: Optional[str] = Field(default="anonymous", description="Developer username")
    branch: Optional[str] = Field(default="main", description="Target git branch")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "prompt": "Add a new payment webhook route that processes Stripe events and updates user subscription status in the database",
                    "project_id": "ecommerce-platform-v2",
                    "author": "hamid.khan",
                    "branch": "feature/stripe-webhooks"
                }
            ]
        }
    }


class ConflictDetail(BaseModel):
    """A single conflict identified between feature spec and adversarial spec."""
    severity: str = Field(..., description="critical | high | medium | low")
    category: str = Field(..., description="security | api_drift | schema_collision | dependency")
    description: str
    affected_component: Optional[str] = None
    remediation: Optional[str] = None


class AuditResult(BaseModel):
    """Full result returned after the Shadow Audit pipeline completes."""
    audit_id: str
    project_id: str
    status: AuditStatus
    prompt_summary: str
    feature_spec_url: Optional[str] = None
    adversarial_spec_url: Optional[str] = None
    conflicts: list[ConflictDetail] = []
    auto_remediation_applied: bool = False
    recommended_tests: list[str] = []
    message: str = ""

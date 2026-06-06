"""
Interceptor API routes — the entry point for all developer prompts.
"""
import uuid
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks

from .models import PromptInterceptRequest, AuditResult, AuditStatus
from ..auditor.engine import AuditEngine
from ..context.parser import ContextParser

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["interceptor"])

# Shared engine instances (singletons for demo; use DI in production)
_audit_engine = AuditEngine()
_context_parser = ContextParser()


@router.post("/intercept", response_model=AuditResult, summary="Intercept & audit a developer prompt")
async def intercept_prompt(request: PromptInterceptRequest, background_tasks: BackgroundTasks):
    """
    Main interception endpoint.

    1. Receives a developer's feature prompt.
    2. Runs the Shadow Audit pipeline (context pull → spec generation → adversarial check).
    3. Returns a fully-reconciled AuditResult with conflicts and remediation advice.
    """
    audit_id = str(uuid.uuid4())
    logger.info("Intercepting prompt | audit_id=%s project=%s", audit_id, request.project_id)

    try:
        result = await _audit_engine.run(
            audit_id=audit_id,
            prompt=request.prompt,
            project_id=request.project_id,
            author=request.author or "anonymous",
            branch=request.branch or "main",
        )
        background_tasks.add_task(_log_audit_result, result)
        return result
    except Exception as exc:
        logger.exception("Audit pipeline failed for audit_id=%s", audit_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/audit/{audit_id}", response_model=AuditResult, summary="Retrieve a past audit result")
async def get_audit(audit_id: str):
    """Fetch a previously computed audit result by ID."""
    result = _audit_engine.get_cached(audit_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id!r} not found")
    return result


@router.get("/health", tags=["ops"], summary="Health check")
async def health():
    return {"status": "ok", "service": "shadow-developer-interceptor"}


def _log_audit_result(result: AuditResult) -> None:
    """Background task: persist audit result to log / storage."""
    logger.info(
        "Audit complete | id=%s status=%s conflicts=%d",
        result.audit_id,
        result.status,
        len(result.conflicts),
    )

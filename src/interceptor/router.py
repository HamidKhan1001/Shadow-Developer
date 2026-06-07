"""
Interceptor API routes — the entry point for all developer prompts.
"""
import uuid
import json
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse

from .models import PromptInterceptRequest, AuditResult, AuditStatus, ConflictDetail
from ..auditor.engine import AuditEngine
from ..database import save_audit, get_audit, list_audits, AuditRecord

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["interceptor"])

_audit_engine = AuditEngine()


# ------------------------------------------------------------------ #
# Root — demo landing page                                             #
# ------------------------------------------------------------------ #

@router.get("/", include_in_schema=False, tags=["ops"])
async def root():
    """Friendly landing page so hitting / doesn't 404."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Shadow Developer</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; background: #0d1117; color: #e6edf3; }
        h1 { color: #58a6ff; } h2 { color: #8b949e; font-weight: 400; }
        a { color: #58a6ff; text-decoration: none; } a:hover { text-decoration: underline; }
        .badge { display: inline-block; background: #238636; color: #fff; padding: 4px 12px; border-radius: 20px; font-size: 13px; margin: 4px; }
        .badge.warn { background: #9e6a03; } .badge.fail { background: #da3633; }
        ul { line-height: 2; } code { background: #161b22; padding: 2px 8px; border-radius: 4px; }
      </style>
    </head>
    <body>
      <h1>🕵️ Shadow Developer</h1>
      <h2>Autonomous Spec-Driven Audit Agent</h2>
      <p>Intercepts AI-generated feature prompts and audits them for security flaws,
         API drift, and architectural conflicts — before a single line of code is written.</p>
      <h3>Quick Links</h3>
      <ul>
        <li><a href="/docs">📖 Swagger UI — try the API live</a></li>
        <li><a href="/redoc">📚 ReDoc — full API reference</a></li>
        <li><a href="/api/v1/history">🗂 Audit History (JSON)</a></li>
        <li><a href="/api/v1/health">💚 Health Check</a></li>
      </ul>
      <h3>Try it — POST to <code>/api/v1/intercept</code></h3>
      <pre style="background:#161b22;padding:16px;border-radius:8px;overflow:auto">{
  "prompt": "Add a payment webhook route without signature verification",
  "project_id": "ecommerce-platform-v2",
  "author": "hamid.khan",
  "branch": "feature/webhooks"
}</pre>
      <h3>Status Legend</h3>
      <span class="badge">PASSED</span>
      <span class="badge warn">NEEDS REVISION</span>
      <span class="badge fail">FAILED</span>
    </body>
    </html>
    """
    return HTMLResponse(html)


# ------------------------------------------------------------------ #
# Intercept                                                            #
# ------------------------------------------------------------------ #

@router.post("/intercept", response_model=AuditResult, summary="Intercept & audit a developer prompt")
async def intercept_prompt(request: PromptInterceptRequest, background_tasks: BackgroundTasks):
    """
    Main interception endpoint.

    1. Receives a developer feature prompt.
    2. Runs security + architectural audit rules.
    3. Persists the result to local SQLite.
    4. Returns a fully-reconciled AuditResult.
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
        background_tasks.add_task(_persist_result, result, request)
        return result
    except Exception as exc:
        logger.exception("Audit pipeline failed for audit_id=%s", audit_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ------------------------------------------------------------------ #
# Retrieve single audit                                                #
# ------------------------------------------------------------------ #

@router.get("/audit/{audit_id}", response_model=AuditResult, summary="Retrieve a past audit result")
async def get_audit_result(audit_id: str):
    """Fetch a previously computed audit result by ID (from DB or in-memory cache)."""
    # Try DB first
    record = await get_audit(audit_id)
    if record:
        return _record_to_result(record)
    # Fall back to in-memory cache
    result = _audit_engine.get_cached(audit_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found")
    return result


# ------------------------------------------------------------------ #
# Audit history                                                        #
# ------------------------------------------------------------------ #

@router.get("/history", summary="List recent audit results")
async def audit_history(limit: int = 20):
    """Returns the most recent audit results stored in the local SQLite database."""
    records = await list_audits(limit=limit)
    return {
        "total": len(records),
        "audits": [
            {
                "audit_id": r.audit_id,
                "project_id": r.project_id,
                "author": r.author,
                "branch": r.branch,
                "status": r.status,
                "prompt_summary": r.prompt_summary,
                "conflicts": len(json.loads(r.conflicts_json)),
                "created_at": r.created_at.isoformat(),
                "message": r.message,
            }
            for r in records
        ],
    }


# ------------------------------------------------------------------ #
# Seed demo data                                                       #
# ------------------------------------------------------------------ #

@router.post("/seed", summary="Seed all demo prompts into the database")
async def seed_demo(background_tasks: BackgroundTasks):
    """
    Runs all 7 demo prompts through the audit pipeline and saves them
    to the local database — great for showing a pre-populated history.
    """
    import json
    from pathlib import Path

    demo_file = Path(__file__).parent.parent.parent / "data" / "demo_prompts.json"
    demos = json.loads(demo_file.read_text())
    seeded = []

    for demo in demos:
        req = demo["request"]
        audit_id = str(uuid.uuid4())
        result = await _audit_engine.run(
            audit_id=audit_id,
            prompt=req["prompt"],
            project_id=req["project_id"],
            author=req.get("author", "demo-user"),
            branch=req.get("branch", "main"),
        )
        await _persist_result(result, PromptInterceptRequest(**req))
        seeded.append({"label": demo["label"], "audit_id": audit_id, "status": result.status})

    return {"seeded": len(seeded), "results": seeded}


# ------------------------------------------------------------------ #
# Health                                                               #
# ------------------------------------------------------------------ #

@router.get("/health", tags=["ops"], summary="Health check")
async def health():
    return {"status": "ok", "service": "shadow-developer-interceptor"}


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

async def _persist_result(result: AuditResult, request: PromptInterceptRequest) -> None:
    """Save audit result to SQLite."""
    try:
        record = AuditRecord(
            audit_id=result.audit_id,
            project_id=result.project_id,
            author=request.author or "anonymous",
            branch=request.branch or "main",
            status=result.status.value,
            prompt_summary=result.prompt_summary,
            conflicts_json=json.dumps([c.model_dump() for c in result.conflicts]),
            tests_json=json.dumps(result.recommended_tests),
            message=result.message,
        )
        await save_audit(record)
    except Exception as exc:
        logger.warning("Failed to persist audit %s: %s", result.audit_id, exc)


def _record_to_result(record: AuditRecord) -> AuditResult:
    """Convert a DB record back into an AuditResult."""
    conflicts = [ConflictDetail(**c) for c in json.loads(record.conflicts_json)]
    return AuditResult(
        audit_id=record.audit_id,
        project_id=record.project_id,
        status=AuditStatus(record.status),
        prompt_summary=record.prompt_summary,
        conflicts=conflicts,
        recommended_tests=json.loads(record.tests_json),
        message=record.message,
    )

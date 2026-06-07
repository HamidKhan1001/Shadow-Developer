"""
Interceptor API routes — the entry point for all developer prompts.
"""
import uuid
import json
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional

from .models import PromptInterceptRequest, AuditResult, AuditStatus, ConflictDetail
from ..auditor.engine import AuditEngine
from ..database import save_audit, get_audit, list_audits, AuditRecord
from ..monitor.code_scanner import CodeScanner
from ..monitor.secret_scanner import SecretScanner

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["interceptor"])

_audit_engine = AuditEngine()
_code_scanner = CodeScanner()
_secret_scanner = SecretScanner()


# ------------------------------------------------------------------ #
# Request models for scan endpoints                                    #
# ------------------------------------------------------------------ #

class CodeScanRequest(BaseModel):
    """Scan an inline code snippet or a directory path."""
    code: Optional[str] = None
    path: Optional[str] = None
    filename: Optional[str] = "<snippet>"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "code": "password = 'hunter2'\ncursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
                    "filename": "example.py"
                }
            ]
        }
    }


class SecretScanRequest(BaseModel):
    """Scan a directory for leaked secrets and .gitignore gaps."""
    path: str = "."

    model_config = {
        "json_schema_extra": {
            "examples": [{"path": "./src"}]
        }
    }

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
        * { box-sizing: border-box; }
        body { font-family: system-ui, sans-serif; max-width: 860px; margin: 60px auto; padding: 0 24px; background: #0d1117; color: #e6edf3; }
        h1 { color: #58a6ff; margin-bottom: 4px; }
        h2 { color: #8b949e; font-weight: 400; margin-top: 0; }
        h3 { color: #cdd9e5; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
        a { color: #58a6ff; text-decoration: none; } a:hover { text-decoration: underline; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
        .card h4 { margin: 0 0 8px; color: #58a6ff; }
        .card ul { margin: 0; padding-left: 18px; line-height: 2; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; margin: 3px; }
        .green { background: #1a4731; color: #3fb950; border: 1px solid #238636; }
        .yellow { background: #3d2c00; color: #d29922; border: 1px solid #9e6a03; }
        .red { background: #3d1c1c; color: #f85149; border: 1px solid #da3633; }
        .blue { background: #0d2149; color: #58a6ff; border: 1px solid #1f6feb; }
        code { background: #161b22; border: 1px solid #30363d; padding: 2px 8px; border-radius: 4px; font-size: 13px; }
        pre { background: #161b22; border: 1px solid #30363d; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
        .tag { display: inline-block; background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 6px; }
      </style>
    </head>
    <body>
      <h1>🕵️ Shadow Developer</h1>
      <h2>Autonomous Spec-Driven Audit Agent &amp; Code Security Monitor</h2>

      <div class="grid">
        <div class="card">
          <h4>📋 Spec Audit</h4>
          <ul>
            <li><a href="/ide">🖥️ Web IDE — full coding environment</a></li>
            <li><a href="/docs">Swagger UI — try the API live</a></li>
            <li><a href="/redoc">ReDoc — full reference</a></li>
            <li><a href="/api/v1/history">Audit History</a></li>
            <li><a href="/api/v1/health">Health Check</a></li>
          </ul>
        </div>
        <div class="card">
          <h4>🔍 Code Monitor</h4>
          <ul>
            <li><a href="/docs#/monitor/scan_code_api_v1_scan_code_post">Scan Code Snippet</a></li>
            <li><a href="/docs#/monitor/scan_secrets_api_v1_scan_secrets_post">Scan for Secrets</a></li>
            <li><a href="/api/v1/scan/gitignore">.gitignore Audit</a></li>
            <li><a href="/api/v1/scan/demo">Run Demo Scan</a></li>
          </ul>
        </div>
      </div>

      <h3>Try the Spec Auditor</h3>
      <pre>POST /api/v1/intercept
{
  "prompt": "Add a payment webhook route without signature verification",
  "project_id": "ecommerce-platform-v2",
  "author": "hamid.khan",
  "branch": "feature/webhooks"
}</pre>

      <h3>Try the Code Monitor</h3>
      <pre>POST /api/v1/scan/code
{
  "code": "password = 'hunter2'\\ncursor.execute(f\\"SELECT * FROM users WHERE id={uid}\\")",
  "filename": "auth.py"
}</pre>

      <h3>Status Legend</h3>
      <span class="badge green">PASSED</span>
      <span class="badge yellow">NEEDS REVISION</span>
      <span class="badge red">FAILED</span>
      <span class="badge red">CRITICAL</span>
      <span class="badge yellow">HIGH</span>
      <span class="badge blue">MEDIUM</span>
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
# Code Monitor — scan for suspicious / security code                  #
# ------------------------------------------------------------------ #

@router.post("/scan/code", tags=["monitor"], summary="Scan code for security issues")
async def scan_code(request: CodeScanRequest):
    """
    Static security scanner — highlights suspicious and security-relevant
    code patterns with exact file paths, line numbers, and severity.

    Supports:
    - **code**: inline Python snippet to scan
    - **path**: directory or file path to scan on disk
    """
    if not request.code and not request.path:
        raise HTTPException(status_code=400, detail="Provide either 'code' (snippet) or 'path' (directory).")

    if request.code:
        result = _code_scanner.scan_code_snippet(request.code, filename=request.filename or "<snippet>")
    else:
        scan_path = Path(request.path)
        if not scan_path.exists():
            raise HTTPException(status_code=404, detail=f"Path '{request.path}' does not exist.")
        if scan_path.is_file():
            result = _code_scanner.scan_file(str(scan_path))
        else:
            result = _code_scanner.scan_directory(str(scan_path))

    return result.to_dict()


@router.post("/scan/secrets", tags=["monitor"], summary="Scan for leaked secrets and .env exposure")
async def scan_secrets(request: SecretScanRequest):
    """
    Secret & environment scanner.

    - Detects hardcoded API keys, passwords, tokens, private keys
    - Audits .gitignore for missing security patterns
    - Flags .env files that are not gitignored
    """
    scan_path = Path(request.path)
    if not scan_path.exists():
        raise HTTPException(status_code=404, detail=f"Path '{request.path}' does not exist.")

    result = _secret_scanner.scan_directory(str(scan_path))
    return result.to_dict()


@router.get("/scan/gitignore", tags=["monitor"], summary="Audit .gitignore completeness")
async def audit_gitignore(path: str = "."):
    """
    Checks the .gitignore at the given path for missing security-critical patterns
    like .env, *.key, *.pem, venv/, etc.
    """
    scan_path = Path(path)
    if not scan_path.exists():
        raise HTTPException(status_code=404, detail=f"Path '{path}' does not exist.")

    report = _secret_scanner.audit_gitignore(str(scan_path))
    return {
        "gitignore_found": report.found,
        "is_sufficient": report.is_sufficient,
        "present_patterns": report.present_patterns,
        "missing_patterns": report.missing_patterns,
        "recommendation": (
            "Add missing patterns to .gitignore to prevent accidental secret commits."
            if report.missing_patterns else
            ".gitignore looks good for security-sensitive patterns."
        ),
    }


@router.post("/scan/demo", tags=["monitor"], summary="Run demo code scan with intentionally bad code")
async def scan_demo():
    """
    Runs the code scanner against demo snippets that contain intentional
    security issues — great for showing what the monitor catches live.
    """
    demo_snippets = [
        {
            "label": "SQL Injection + hardcoded password",
            "code": (
                "password = 'supersecret123'\n"
                "api_key = 'sk-abcdef1234567890abcdef'\n"
                "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
                "result = cursor.execute(\"SELECT * FROM orders WHERE name='\" + name + \"'\")\n"
            ),
            "filename": "demo_bad_code.py",
        },
        {
            "label": "Auth bypass + weak crypto + debug mode",
            "code": (
                "DEBUG = True\n"
                "SECRET_KEY = 'abc123'\n"
                "import hashlib\n"
                "token_hash = hashlib.md5(token.encode()).hexdigest()\n"
                "# TODO: skip auth for now\n"
                "subprocess.call('rm -rf /tmp/' + user_dir, shell=True)\n"
            ),
            "filename": "demo_auth_issues.py",
        },
        {
            "label": "Safe code — should have zero findings",
            "code": (
                "import os\n"
                "import hashlib\n"
                "import secrets\n"
                "password = os.getenv('DB_PASSWORD')\n"
                "api_key = os.getenv('API_KEY')\n"
                "token = secrets.token_hex(32)\n"
                "token_hash = hashlib.sha256(token.encode()).hexdigest()\n"
            ),
            "filename": "demo_safe_code.py",
        },
    ]

    results = []
    for demo in demo_snippets:
        scan = _code_scanner.scan_code_snippet(demo["code"], filename=demo["filename"])
        results.append({
            "label": demo["label"],
            "filename": demo["filename"],
            "total_findings": len(scan.findings),
            "summary": scan.summary,
            "findings": [f.to_dict() for f in scan.findings],
        })

    return {"demo_scans": results}



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

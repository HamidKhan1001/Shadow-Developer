"""
Shadow Developer IDE -- serves the web-based coding IDE interface.
"""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

ide_router = APIRouter(tags=["ide"])

_STATIC = Path(__file__).parent.parent / "static"


@ide_router.get("/ide", include_in_schema=False)
async def serve_ide():
    """Serve the Shadow Developer Web IDE."""
    html = (_STATIC / "ide.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@ide_router.get("/landing", include_in_schema=False)
async def serve_landing():
    """Serve the Shadow Developer landing page."""
    html = (_STATIC / "landing.html").read_text(encoding="utf-8")
    return HTMLResponse(html)

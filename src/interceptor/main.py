"""
FastAPI application entry point for Shadow Developer Interceptor.

Run locally:
    uvicorn src.interceptor.main:app --host 0.0.0.0 --port 8000 --reload
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from .router import router
from ..config import get_settings
from ..database import init_db

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Shadow Developer starting up (env=%s)", settings.app_env)
    await init_db()
    logger.info("SQLite database ready at shadow_dev.db")
    yield
    logger.info("Shadow Developer shutting down")


app = FastAPI(
    title="Shadow Developer",
    description=(
        "Autonomous spec-driven audit agent. Intercepts AI-generated feature prompts "
        "and validates them for security flaws, API drift, and architectural conflicts "
        "before any production code is written."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect bare root to the API landing page."""
    return RedirectResponse(url="/api/v1/")

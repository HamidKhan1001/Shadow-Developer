"""
FastAPI application entry point for Shadow Developer Interceptor.

Run locally:
    uvicorn src.interceptor.main:app --host 0.0.0.0 --port 8000 --reload
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .router import router
from ..config import get_settings

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Shadow Developer Interceptor starting up (env=%s)", settings.app_env)
    yield
    logger.info("Shadow Developer Interceptor shutting down")


app = FastAPI(
    title="Shadow Developer API",
    description=(
        "Autonomous, spec-driven audit agent that intercepts AI-generated feature "
        "specifications and validates them for security, API drift, and architectural "
        "consistency before any production code is written."
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

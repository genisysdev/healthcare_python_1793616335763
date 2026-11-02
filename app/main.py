"""
Healthcare AI Platform - Main Application Entry Point
Patient Data Privacy & Safety Compliant FastAPI Service
"""

import ssl
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.endpoints import patients, diagnostics, summaries, audit, fhir_export
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.middleware.audit_middleware import AuditLoggerMiddleware
from app.middleware.mtls_middleware import MTLSMiddleware
from app.db.session import engine, Base

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup & shutdown."""
    setup_logging()
    logger.info("Healthcare AI Platform starting up...")
    # Create DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized.")
    yield
    logger.info("Healthcare AI Platform shutting down.")
    await engine.dispose()


app = FastAPI(
    title="Healthcare AI Platform",
    description=(
        "HIPAA-compliant, FHIR-ready clinical AI service with PHI redaction, "
        "audit logging, mTLS, fairness auditing, and XAI diagnostics."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)

# ── Security Middleware Stack ──────────────────────────────────────────────────
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
# Audit Logger Middleware — logs every PHI-touching request (Access Trace / Security Hook)
app.add_middleware(AuditLoggerMiddleware)
# mTLS enforcement middleware (mTLS Context / Cert Required)
app.add_middleware(MTLSMiddleware)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(patients.router,    prefix="/api/v1/patients",    tags=["Patients"])
app.include_router(diagnostics.router, prefix="/api/v1/diagnostics", tags=["Diagnostics"])
app.include_router(summaries.router,   prefix="/api/v1/summaries",   tags=["Summaries"])
app.include_router(audit.router,       prefix="/api/v1/audit",       tags=["Audit"])
app.include_router(fhir_export.router, prefix="/api/v1/fhir",        tags=["FHIR"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "Healthcare AI Platform", "version": "1.0.0"}

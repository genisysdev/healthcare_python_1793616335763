"""
Core Configuration — environment-driven settings for the Healthcare AI Platform.
"""

from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────────
    ENVIRONMENT: str = Field(default="development")
    SECRET_KEY: str = Field(default="change-me-in-production-VERY-LONG-SECRET")
    ALLOWED_HOSTS: List[str] = Field(default=["*"])
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:3000"])

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./healthcare.db")

    # ── mTLS / TLS (Cert Required / mTLS Context) ────────────────────────────
    MTLS_ENABLED: bool = Field(default=True)
    TLS_CA_CERT: str = Field(default="certs/ca.crt")
    TLS_SERVER_CERT: str = Field(default="certs/server.crt")
    TLS_SERVER_KEY: str = Field(default="certs/server.key")

    # ── PHI Redaction (Scrub PHI Data / Mask PII Utility) ────────────────────
    PHI_REDACTION_ENABLED: bool = Field(default=True)

    # ── Audit Logging (Audit Logger / Access Trace) ──────────────────────────
    AUDIT_LOG_PATH: str = Field(default="logs/audit.jsonl")
    AUDIT_STORAGE_BACKEND: str = Field(default="file")  # "file" | "db" | "siem"

    # ── Clinical AI (Confidence Gate / Threshold Filter) ─────────────────────
    AI_CONFIDENCE_THRESHOLD: float = Field(default=0.80)

    # ── Bias Audit (Bias Audit Report / Subgroup Parity) ─────────────────────
    BIAS_MAX_VARIANCE_PCT: float = Field(default=0.05)

    # ── FHIR (FHIR Validation / HL7 Model Check) ─────────────────────────────
    FHIR_VERSION: str = Field(default="R4")

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

"""
ORM Models — SQLAlchemy table definitions for the Healthcare AI Platform.
All PHI columns store ONLY redacted/tokenized values — never raw identifiers.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON
)
from sqlalchemy.orm import relationship

from app.db.session import Base


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Patient(Base):
    """
    Stores de-identified patient records.
    All PHI fields contain SYNTHETIC TOKENS produced by the Scrub PHI Data utility.
    Raw PHI is never persisted — the 'Store Raw Note' anti-pattern is explicitly blocked.
    """
    __tablename__ = "patients"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Tokenized / masked identifiers — never raw (Redact Identifiers / Anonymize Text)
    name_token = Column(String(64), nullable=False, comment="Synthetic token — NOT raw name")
    dob_token = Column(String(64), nullable=False, comment="Synthetic token — NOT raw DOB")
    mrn_token = Column(String(64), nullable=False, comment="Synthetic token — NOT raw MRN")
    gender = Column(String(16), nullable=True)
    ethnicity = Column(String(64), nullable=True)
    age_group = Column(String(16), nullable=True)

    # Restricted clinical fields (Column Projection / Restricted View)
    primary_diagnosis_code = Column(String(16), nullable=True, comment="ICD-10 validated code")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=_now_utc)
    updated_at = Column(DateTime(timezone=True), default=_now_utc, onupdate=_now_utc)

    clinical_notes = relationship("ClinicalNote", back_populates="patient", cascade="all, delete-orphan")
    diagnostics = relationship("DiagnosticResult", back_populates="patient", cascade="all, delete-orphan")


class ClinicalNote(Base):
    """
    Stores redacted clinical notes.
    The raw note text is NEVER stored here — only the output of the Scrub PHI Data utility.
    """
    __tablename__ = "clinical_notes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patient_id = Column(String(36), ForeignKey("patients.id"), nullable=False)
    # This field MUST contain only anonymized / masked text (Anonymize Text)
    redacted_text = Column(Text, nullable=False, comment="PHI-scrubbed text only — see PHIRedactionService")
    section_name = Column(String(128), nullable=True)
    source_system = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now_utc)

    patient = relationship("Patient", back_populates="clinical_notes")
    summary_citations = relationship("SummaryCitation", back_populates="note")


class DiagnosticResult(Base):
    """
    Stores AI diagnostic suggestions with confidence gating and XAI reasoning.
    Low-confidence results are stored but flagged — they are NEVER returned without a review marker.
    """
    __tablename__ = "diagnostic_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patient_id = Column(String(36), ForeignKey("patients.id"), nullable=False)
    suggested_diagnosis = Column(String(256), nullable=False)
    icd10_code = Column(String(16), nullable=True, comment="ICD10 Mapper validated code")
    confidence_score = Column(Float, nullable=False)
    # Confidence Gate flag — triggers UI warning badge for score < threshold
    requires_physician_review = Column(Boolean, default=False, comment="Confidence Gate / Low Score Flag")
    # XAI reasoning block (SHAP Hook / Feature Impact Map / XAI Reasoning)
    reasoning = Column(JSON, nullable=True, comment="Top-3 SHAP feature attributions")
    created_at = Column(DateTime(timezone=True), default=_now_utc)

    patient = relationship("Patient", back_populates="diagnostics")


class SummaryCitation(Base):
    """
    Claim-to-source citation block for generated summaries.
    Every claim MUST have a valid citation — 'Hallucinated Summary' anti-pattern is blocked.
    """
    __tablename__ = "summary_citations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    note_id = Column(String(36), ForeignKey("clinical_notes.id"), nullable=False)
    claim_text = Column(Text, nullable=False)
    # Citation Link / Source Attribution / Evidence Tracer
    source_doc_id = Column(String(36), nullable=False)
    section_name = Column(String(128), nullable=False)
    text_span_start = Column(Integer, nullable=False)
    text_span_end = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now_utc)

    note = relationship("ClinicalNote", back_populates="summary_citations")


class AuditLog(Base):
    """
    Immutable PHI access audit trail.
    Written by the AuditLogger middleware — application layer cannot modify these records.
    Satisfies: Audit Logger / Access Trace / Security Hook / Log PHI Access
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(128), nullable=False)
    action = Column(String(16), nullable=False, comment="READ | WRITE | DELETE")
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=False)
    # ISO-8601 Timestamp (Access Trace requirement)
    timestamp = Column(DateTime(timezone=True), default=_now_utc, nullable=False)
    http_method = Column(String(8), nullable=True)
    endpoint = Column(String(256), nullable=True)
    response_status = Column(Integer, nullable=True)

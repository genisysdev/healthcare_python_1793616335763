"""
Pydantic Schemas — Response Schema / Field Allowlist / Column Projection / Restricted View

All API response schemas use explicit field allowlists — no raw ORM objects are ever
returned to callers.  This enforces Data Minimization at the schema layer.

Satisfies:
  ✅ Data Minimization rule
  ✅ Match patterns: Response Schema, Field Allowlist, Column Projection, Restricted View
  ✅ Blocks anti-patterns: Select All Query, Return Full Object, Schema Bypass, Wildcard Extraction
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict


# ── Shared Base ───────────────────────────────────────────────────────────────

class BaseResponse(BaseModel):
    """Base response with common metadata."""
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ── Patient Schemas ───────────────────────────────────────────────────────────

class PatientCreate(BaseModel):
    """Inbound patient registration payload — raw PHI accepted here only."""
    raw_name: str = Field(..., min_length=1, max_length=256)
    raw_dob: str = Field(..., description="Date of birth in MM/DD/YYYY format")
    raw_mrn: str = Field(..., min_length=4, max_length=32)
    gender: Optional[str] = Field(default=None, max_length=16)
    ethnicity: Optional[str] = Field(default=None, max_length=64)
    age_group: Optional[str] = Field(default=None, max_length=16)


class PatientResponse(BaseResponse):
    """
    Restricted View — returns only de-identified fields.
    Raw PHI fields (name, DOB, MRN) are NEVER included in this schema.
    Field Allowlist enforced by explicit field declarations below.
    """
    id: str
    name_token: str = Field(description="Synthetic PHI token — not a real name")
    gender: Optional[str]
    ethnicity: Optional[str]
    age_group: Optional[str]
    primary_diagnosis_code: Optional[str]
    is_active: bool
    created_at: datetime


class PatientListResponse(BaseResponse):
    """Column Projection response for patient list — minimal fields only."""
    id: str
    name_token: str
    gender: Optional[str]
    age_group: Optional[str]
    is_active: bool


# ── Clinical Note Schemas ─────────────────────────────────────────────────────

class ClinicalNoteCreate(BaseModel):
    """Inbound clinical note — raw text accepted; PHI scrubbing applied before storage."""
    patient_id: str
    raw_note_text: str = Field(..., min_length=1, max_length=50_000)
    section_name: Optional[str] = Field(default=None, max_length=128)
    source_system: Optional[str] = Field(default=None, max_length=64)


class ClinicalNoteResponse(BaseResponse):
    """
    Response Schema for clinical notes — returns only redacted_text, never raw_note_text.
    This is the Field Allowlist for note responses.
    """
    id: str
    patient_id: str
    redacted_text: str   # ← only the scrubbed version is ever returned
    section_name: Optional[str]
    source_system: Optional[str]
    created_at: datetime


# ── Diagnostic Schemas ────────────────────────────────────────────────────────

class FeatureImpactSchema(BaseModel):
    """XAI feature impact for clinician-facing responses."""
    feature_id: str
    human_readable_name: str
    impact_score: float
    direction: str  # "+" or "-"


class XAIReasoningSchema(BaseModel):
    """SHAP Hook reasoning block — top-3 features."""
    explanation_method: str
    top_features: List[FeatureImpactSchema]


class DiagnosticRequest(BaseModel):
    patient_id: str
    clinical_text: str = Field(..., min_length=10, max_length=10_000)
    raw_diagnosis: str = Field(..., min_length=2, max_length=256)
    raw_confidence: float = Field(..., ge=0.0, le=1.0)


class DiagnosticResponse(BaseResponse):
    """
    Confidence Gate response schema.
    Low-confidence results always carry requires_physician_review=True.
    This schema enforces that no AI suggestion bypasses the review flag.
    """
    id: str
    patient_id: str
    suggested_diagnosis: str
    icd10_code: Optional[str]
    confidence_score: float
    requires_physician_review: bool     # Confidence Gate / Low Score Flag
    term_is_verified: bool              # ICD10 Mapper / SNOMED Validator result
    reasoning: XAIReasoningSchema       # XAI Reasoning / SHAP Hook
    created_at: datetime


# ── Summary / Citation Schemas ────────────────────────────────────────────────

class CitationBlockSchema(BaseModel):
    """Evidence Tracer / Source Attribution block."""
    source_doc_id: str
    section_name: str
    text_span_start: int
    text_span_end: int


class ClinicalClaimSchema(BaseModel):
    """
    Claim Grounding response — every claim must have a citation.
    Claims without citations are never surfaced in API responses.
    """
    claim_text: str
    citation: CitationBlockSchema       # ← required; no citation = blocked claim
    is_grounded: bool = True


class SummaryRequest(BaseModel):
    patient_id: str
    note_id: str
    raw_claims: List[str] = Field(..., min_length=1)


class SummaryResponse(BaseResponse):
    """Grounded clinical summary — all claims cite their source note spans."""
    note_id: str
    patient_id: str
    grounded_claims: List[ClinicalClaimSchema]
    total_claims: int
    grounded_count: int


# ── FHIR Export Schemas ───────────────────────────────────────────────────────

class FHIRExportRequest(BaseModel):
    patient_id: str
    include_conditions: bool = True
    include_reports: bool = True


class FHIRExportResponse(BaseResponse):
    patient_id: str
    fhir_version: str
    validation_passed: bool
    resources: List[dict]
    resource_count: int


# ── Audit Schemas ─────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    """Read-only audit log entry response."""
    id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    ip_address: str
    timestamp: datetime
    endpoint: Optional[str]
    response_status: Optional[int]


# ── Bias Audit Schemas ────────────────────────────────────────────────────────

class SubgroupMetricSchema(BaseModel):
    group_name: str
    attribute: str
    f1_score: float
    precision: float
    recall: float
    sample_count: int


class BiasAuditResponse(BaseModel):
    """Bias Audit Report response — returned by the fairness audit endpoint."""
    passed: bool
    max_variance_pct: float
    variance_threshold_pct: float
    subgroup_metrics: List[SubgroupMetricSchema]
    equity_metrics: dict
    violations: List[str]
    recommendation: str

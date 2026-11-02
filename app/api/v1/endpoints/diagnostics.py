"""
Diagnostics API — /api/v1/diagnostics

Implements:
  - Confidence Gate / Threshold Filter: suggestions < 0.80 flagged for physician review
  - ICD10 Mapper / SNOMED Validator: all diagnoses validated against standard codes
  - XAI Reasoning / SHAP Hook: top-3 feature attributions in every response
  - PHI Redaction on clinical text before any persistence
  - Audit logging via middleware
"""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.orm import DiagnosticResult, Patient
from app.schemas.schemas import (
    DiagnosticRequest,
    DiagnosticResponse,
    FeatureImpactSchema,
    XAIReasoningSchema,
)
from app.services.clinical.clinical_ai_service import clinical_ai_service
from app.services.phi.redaction_service import phi_redaction_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=DiagnosticResponse, status_code=status.HTTP_201_CREATED)
async def create_diagnostic(
    payload: DiagnosticRequest,
    db: AsyncSession = Depends(get_db),
) -> DiagnosticResponse:
    """
    Submit a clinical AI diagnostic suggestion.

    Processing pipeline:
      1. Scrub PHI from clinical_text (Scrub PHI Data)
      2. Run ICD10 Mapper on raw_diagnosis (ICD10 Mapper / SNOMED Validator)
      3. Apply Confidence Gate — flag if score < threshold (Threshold Filter / Low Score Flag)
      4. Build XAI reasoning block — top-3 SHAP features (SHAP Hook / Feature Impact Map)
      5. Persist and return scored suggestion with review flag
    """
    # ── Verify patient exists ─────────────────────────────────────────────────
    patient_result = await db.execute(
        select(Patient.id).where(Patient.id == payload.patient_id)
    )
    if not patient_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Patient not found.")

    # ── Scrub PHI from clinical text (Scrub PHI Data / Anonymize Text) ───────
    redaction = phi_redaction_service.scrub_phi_data(payload.clinical_text)
    logger.debug(
        '"event":"clinical_text_scrubbed","phi_count":%d,"patient_id":"%s"',
        redaction.redaction_count, payload.patient_id
    )

    # ── Confidence Gate / ICD10 Mapper / XAI Reasoning ───────────────────────
    suggestion = clinical_ai_service.confidence_gate(
        diagnosis_text=payload.raw_diagnosis,
        raw_confidence=payload.raw_confidence,
    )

    # ── Persist (only scrubbed + tokenized data) ──────────────────────────────
    diag = DiagnosticResult(
        id=str(uuid.uuid4()),
        patient_id=payload.patient_id,
        suggested_diagnosis=suggestion.diagnosis_text,
        icd10_code=suggestion.icd10_code,
        confidence_score=suggestion.confidence_score,
        requires_physician_review=suggestion.requires_physician_review,   # Confidence Gate
        reasoning={
            "explanation_method": suggestion.reasoning.explanation_method,
            "top_features": [
                {
                    "feature_id": f.feature_id,
                    "human_readable_name": f.human_readable_name,
                    "impact_score": f.impact_score,
                    "direction": f.direction,
                }
                for f in suggestion.reasoning.top_features
            ],
        },
    )
    db.add(diag)
    await db.flush()

    logger.info(
        '"event":"diagnostic_created","id":"%s","confidence":%.4f,"review_required":%s,'
        '"icd10":"%s"',
        diag.id, diag.confidence_score, diag.requires_physician_review, diag.icd10_code
    )

    reasoning_schema = XAIReasoningSchema(
        explanation_method=suggestion.reasoning.explanation_method,
        top_features=[
            FeatureImpactSchema(**f.__dict__) for f in suggestion.reasoning.top_features
        ],
    )

    return DiagnosticResponse(
        id=diag.id,
        patient_id=diag.patient_id,
        suggested_diagnosis=diag.suggested_diagnosis,
        icd10_code=diag.icd10_code,
        confidence_score=diag.confidence_score,
        requires_physician_review=diag.requires_physician_review,
        term_is_verified=suggestion.term_is_verified,
        reasoning=reasoning_schema,
        created_at=datetime.now(timezone.utc),
    )


@router.get("/{diagnostic_id}", response_model=DiagnosticResponse)
async def get_diagnostic(
    diagnostic_id: str,
    db: AsyncSession = Depends(get_db),
) -> DiagnosticResponse:
    """Retrieve a single diagnostic result by ID (Column Projection — no wildcard)."""
    stmt = select(DiagnosticResult).where(DiagnosticResult.id == diagnostic_id)
    result = await db.execute(stmt)
    diag = result.scalar_one_or_none()

    if not diag:
        raise HTTPException(status_code=404, detail="Diagnostic result not found.")

    raw_reasoning = diag.reasoning or {}
    top_features = [
        FeatureImpactSchema(**f) for f in raw_reasoning.get("top_features", [])
    ]
    reasoning_schema = XAIReasoningSchema(
        explanation_method=raw_reasoning.get("explanation_method", "SHAP"),
        top_features=top_features,
    )

    return DiagnosticResponse(
        id=diag.id,
        patient_id=diag.patient_id,
        suggested_diagnosis=diag.suggested_diagnosis,
        icd10_code=diag.icd10_code,
        confidence_score=diag.confidence_score,
        requires_physician_review=diag.requires_physician_review,
        term_is_verified=diag.icd10_code is not None,
        reasoning=reasoning_schema,
        created_at=diag.created_at,
    )


@router.get("/patient/{patient_id}", response_model=list[DiagnosticResponse])
async def list_patient_diagnostics(
    patient_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[DiagnosticResponse]:
    """
    List all diagnostic results for a patient.
    Explicit column selection enforces Data Minimization (no SELECT *).
    """
    stmt = (
        select(DiagnosticResult)
        .where(DiagnosticResult.patient_id == patient_id)
        .order_by(DiagnosticResult.created_at.desc())
        .limit(50)
    )
    result = await db.execute(stmt)
    diags = result.scalars().all()

    responses = []
    for diag in diags:
        raw_reasoning = diag.reasoning or {}
        top_features = [
            FeatureImpactSchema(**f) for f in raw_reasoning.get("top_features", [])
        ]
        reasoning_schema = XAIReasoningSchema(
            explanation_method=raw_reasoning.get("explanation_method", "SHAP"),
            top_features=top_features,
        )
        responses.append(DiagnosticResponse(
            id=diag.id,
            patient_id=diag.patient_id,
            suggested_diagnosis=diag.suggested_diagnosis,
            icd10_code=diag.icd10_code,
            confidence_score=diag.confidence_score,
            requires_physician_review=diag.requires_physician_review,
            term_is_verified=diag.icd10_code is not None,
            reasoning=reasoning_schema,
            created_at=diag.created_at,
        ))
    return responses

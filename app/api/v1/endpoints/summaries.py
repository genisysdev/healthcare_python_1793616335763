"""
Summaries API — /api/v1/summaries

Implements Evidence-Based Citations:
  - Every clinical claim must be grounded to a source note span (Claim Grounding)
  - Ungrounded claims (Hallucinated Summary) are blocked before reaching the API response
  - Citation blocks contain source_doc_id, section_name, and text_span offsets
"""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.orm import ClinicalNote, Patient, SummaryCitation
from app.schemas.schemas import (
    CitationBlockSchema,
    ClinicalClaimSchema,
    ClinicalNoteCreate,
    ClinicalNoteResponse,
    SummaryRequest,
    SummaryResponse,
)
from app.services.clinical.clinical_ai_service import clinical_ai_service
from app.services.phi.redaction_service import phi_redaction_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/notes", response_model=ClinicalNoteResponse, status_code=status.HTTP_201_CREATED)
async def ingest_clinical_note(
    payload: ClinicalNoteCreate,
    db: AsyncSession = Depends(get_db),
) -> ClinicalNoteResponse:
    """
    Ingest a raw clinical note.

    Pipeline:
      1. raw_note_text passes through Scrub PHI Data utility
      2. Only redacted_text is persisted via session.add()
      3. raw_note_text is discarded after scrubbing — never stored (Store Raw Note blocked)
    """
    # ── Scrub PHI Data — mandatory before session.add() ──────────────────────
    redaction = phi_redaction_service.scrub_phi_data(payload.raw_note_text)
    redacted_text = redaction.redacted_text

    # ── Verify patient exists ─────────────────────────────────────────────────
    patient_check = await db.execute(
        select(Patient.id).where(Patient.id == payload.patient_id)
    )
    if not patient_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Patient not found.")

    note = ClinicalNote(
        id=str(uuid.uuid4()),
        patient_id=payload.patient_id,
        redacted_text=redacted_text,          # Only anonymized text stored
        section_name=payload.section_name,
        source_system=payload.source_system,
    )
    db.add(note)
    await db.flush()

    logger.info(
        '"event":"clinical_note_ingested","note_id":"%s","phi_found":%d',
        note.id, redaction.redaction_count
    )
    return ClinicalNoteResponse.model_validate(note)


@router.post("/", response_model=SummaryResponse, status_code=status.HTTP_201_CREATED)
async def generate_summary(
    payload: SummaryRequest,
    db: AsyncSession = Depends(get_db),
) -> SummaryResponse:
    """
    Generate an evidence-based clinical summary.

    All claims are validated via Claim Grounding before inclusion.
    Ungrounded claims (Citationless Output / Hallucinated Summary) are dropped.
    Each claim in the response includes a Citation Link with source span offsets.
    """
    # ── Fetch the source clinical note ────────────────────────────────────────
    note_result = await db.execute(
        select(ClinicalNote).where(
            ClinicalNote.id == payload.note_id,
            ClinicalNote.patient_id == payload.patient_id,
        )
    )
    note = note_result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Clinical note not found.")

    # ── Build grounded summary — Claim Grounding / Evidence Tracer ───────────
    grounded_claims = clinical_ai_service.build_grounded_summary(
        raw_claims=payload.raw_claims,
        source_note_text=note.redacted_text,
        source_doc_id=note.id,
        section_name=note.section_name or "clinical_summary",
    )

    if not grounded_claims:
        raise HTTPException(
            status_code=422,
            detail=(
                "No claims could be grounded against the source note. "
                "All claims must cite a verifiable span in the source document."
            ),
        )

    # ── Persist citations ─────────────────────────────────────────────────────
    citation_schemas: list[ClinicalClaimSchema] = []
    for claim in grounded_claims:
        citation = claim.citation
        db_citation = SummaryCitation(
            id=str(uuid.uuid4()),
            note_id=note.id,
            claim_text=claim.claim_text,
            source_doc_id=citation.source_doc_id,
            section_name=citation.section_name,
            text_span_start=citation.text_span_start,
            text_span_end=citation.text_span_end,
        )
        db.add(db_citation)

        citation_schemas.append(ClinicalClaimSchema(
            claim_text=claim.claim_text,
            citation=CitationBlockSchema(
                source_doc_id=citation.source_doc_id,
                section_name=citation.section_name,
                text_span_start=citation.text_span_start,
                text_span_end=citation.text_span_end,
            ),
            is_grounded=True,
        ))

    await db.flush()
    logger.info(
        '"event":"summary_generated","note_id":"%s","grounded_claims":%d',
        note.id, len(grounded_claims)
    )

    return SummaryResponse(
        note_id=note.id,
        patient_id=payload.patient_id,
        grounded_claims=citation_schemas,
        total_claims=len(payload.raw_claims),
        grounded_count=len(grounded_claims),
    )

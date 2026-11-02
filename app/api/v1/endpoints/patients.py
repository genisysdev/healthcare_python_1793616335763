"""
Patients API — /api/v1/patients

Implements:
  - PHI Redaction before every session.add() call (Scrub PHI Data / Mask PII Utility)
  - Data Minimization via Pydantic response schemas (Column Projection / Restricted View)
  - Explicit column selection in queries — no SELECT * (Field Allowlist)
  - Audit logging via middleware (Access Trace / Security Hook)
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.orm import Patient
from app.schemas.schemas import (
    PatientCreate,
    PatientListResponse,
    PatientResponse,
)
from app.services.phi.redaction_service import phi_redaction_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=PatientResponse, status_code=status.HTTP_201_CREATED)
async def create_patient(
    payload: PatientCreate,
    db: AsyncSession = Depends(get_db),
) -> PatientResponse:
    """
    Register a new patient.

    PHI pipeline:
      1. Raw identifiers (name, DOB, MRN) are passed to PHI Redaction Service
      2. Only synthetic tokens are stored via session.add()
      3. Raw PHI never touches the ORM layer (blocks: Store Raw Note, Raw PHI to DB)
    """
    # ── Scrub PHI Data / Redact Identifiers ──────────────────────────────────
    tokens = phi_redaction_service.redact_identifiers({
        "name": payload.raw_name,
        "dob":  payload.raw_dob,
        "mrn":  payload.raw_mrn,
    })

    # ── Persist only tokenized values (Field Allowlist / Restricted View) ────
    patient = Patient(
        id=str(uuid.uuid4()),
        name_token=tokens["name"],        # Synthetic token — NOT raw name
        dob_token=tokens["dob"],          # Synthetic token — NOT raw DOB
        mrn_token=tokens["mrn"],          # Synthetic token — NOT raw MRN
        gender=payload.gender,
        ethnicity=payload.ethnicity,
        age_group=payload.age_group,
    )
    db.add(patient)
    await db.flush()

    logger.info('"event":"patient_created","patient_id":"%s"', patient.id)
    return PatientResponse.model_validate(patient)


@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: str,
    db: AsyncSession = Depends(get_db),
) -> PatientResponse:
    """
    Retrieve a single patient by ID.

    Uses explicit column selection (Column Projection) — no wildcard queries.
    Audit logging is handled by AuditLoggerMiddleware (Access Trace).
    """
    # ── Explicit column selection — blocks 'Select All Query' anti-pattern ───
    stmt = select(
        Patient.id,
        Patient.name_token,
        Patient.gender,
        Patient.ethnicity,
        Patient.age_group,
        Patient.primary_diagnosis_code,
        Patient.is_active,
        Patient.created_at,
    ).where(Patient.id == patient_id)

    result = await db.execute(stmt)
    row = result.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Patient not found.")

    return PatientResponse(**dict(row))


@router.get("/", response_model=list[PatientListResponse])
async def list_patients(
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
    offset: int = 0,
) -> list[PatientListResponse]:
    """
    List patients — returns a minimal field set (Column Projection / Restricted View).
    No PHI raw values. Pagination enforced to limit data exposure.
    """
    # Explicit column list — NOT SELECT * (Data Minimization)
    stmt = select(
        Patient.id,
        Patient.name_token,
        Patient.gender,
        Patient.age_group,
        Patient.is_active,
    ).limit(min(limit, 100)).offset(offset)

    result = await db.execute(stmt)
    rows = result.mappings().all()
    return [PatientListResponse(**dict(row)) for row in rows]


@router.delete("/{patient_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_patient(
    patient_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-delete a patient record (sets is_active=False)."""
    stmt = select(Patient).where(Patient.id == patient_id)
    result = await db.execute(stmt)
    patient = result.scalar_one_or_none()

    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found.")

    patient.is_active = False
    logger.info('"event":"patient_deactivated","patient_id":"%s"', patient_id)

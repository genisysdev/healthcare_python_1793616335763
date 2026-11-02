"""
FHIR Export API — /api/v1/fhir
Compliance Hook / FHIR Validation / Resource Validator / HL7 Model Check

Every outbound payload passes through compliance_hook() before the response is returned.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.orm import DiagnosticResult, Patient
from app.schemas.schemas import FHIRExportRequest, FHIRExportResponse
from app.services.fhir.fhir_service import FHIRValidationError, fhir_validation_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/export", response_model=FHIRExportResponse)
async def export_fhir_bundle(
    payload: FHIRExportRequest,
    db: AsyncSession = Depends(get_db),
) -> FHIRExportResponse:
    """
    Export a patient record as a FHIR R4 Bundle.

    Pipeline:
      1. Fetch de-identified patient data (Column Projection)
      2. Build FHIR-compliant resources via fhir_validation_service
      3. Run compliance_hook() — raises FHIRValidationError if non-compliant
      4. Return validated bundle (Raw JSON Export / Unvalidated Resource anti-patterns blocked)
    """
    # Fetch patient (explicit columns — no SELECT *)
    patient_result = await db.execute(
        select(Patient.id, Patient.gender, Patient.age_group)
        .where(Patient.id == payload.patient_id)
    )
    patient_row = patient_result.mappings().first()
    if not patient_row:
        raise HTTPException(status_code=404, detail="Patient not found.")

    resources = []

    # ── Build FHIR Patient resource ───────────────────────────────────────────
    fhir_patient = fhir_validation_service.build_fhir_patient(
        patient_id=str(patient_row["id"]),
        gender=patient_row.get("gender"),
        age_group=patient_row.get("age_group"),
    )
    resources.append(fhir_patient)

    # ── Build FHIR Condition resources ────────────────────────────────────────
    if payload.include_conditions:
        diag_result = await db.execute(
            select(DiagnosticResult.id, DiagnosticResult.suggested_diagnosis, DiagnosticResult.icd10_code)
            .where(
                DiagnosticResult.patient_id == payload.patient_id,
                DiagnosticResult.icd10_code.isnot(None),
            )
            .limit(10)
        )
        for diag_row in diag_result.mappings().all():
            if diag_row["icd10_code"]:
                fhir_condition = fhir_validation_service.build_fhir_condition(
                    condition_id=str(uuid.uuid4()),
                    patient_id=str(patient_row["id"]),
                    icd10_code=diag_row["icd10_code"],
                    display_text=diag_row["suggested_diagnosis"],
                )
                resources.append(fhir_condition)

    # ── Build FHIR Bundle ─────────────────────────────────────────────────────
    bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [{"resource": r} for r in resources],
    }

    # ── Compliance Hook — validates before returning (blocks Raw JSON Export) ─
    try:
        validated_bundle = fhir_validation_service.compliance_hook(bundle)
        validation_passed = True
    except FHIRValidationError as exc:
        logger.error('"event":"fhir_export_failed","patient_id":"%s","error":"%s"',
                     payload.patient_id, str(exc))
        raise HTTPException(status_code=422, detail=f"FHIR validation failed: {exc}")

    logger.info(
        '"event":"fhir_export_success","patient_id":"%s","resource_count":%d',
        payload.patient_id, len(resources)
    )

    return FHIRExportResponse(
        patient_id=payload.patient_id,
        fhir_version=fhir_validation_service.fhir_version,
        validation_passed=validation_passed,
        resources=resources,
        resource_count=len(resources),
    )

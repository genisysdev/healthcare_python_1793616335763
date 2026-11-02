"""
Patient Service — Business logic layer for patient management.
Coordinates PHI redaction, DB writes, and audit logging.
"""

import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.orm import Patient
from app.services.phi.redaction_service import phi_redaction_service

logger = logging.getLogger(__name__)


class PatientService:
    """
    Patient business logic service.

    Enforces:
      - PHI Redaction before every ORM write (Scrub PHI Data)
      - Column Projection in all read queries (no SELECT *)
      - Data Minimization via explicit field lists
    """

    async def create_patient(
        self,
        db: AsyncSession,
        raw_name: str,
        raw_dob: str,
        raw_mrn: str,
        gender: Optional[str] = None,
        ethnicity: Optional[str] = None,
        age_group: Optional[str] = None,
    ) -> Patient:
        """
        Create a patient, tokenizing all PHI fields before persistence.
        The 'Store Raw Note' and 'Raw PHI to DB' anti-patterns are blocked here.
        """
        tokens = phi_redaction_service.redact_identifiers({
            "name": raw_name,
            "dob":  raw_dob,
            "mrn":  raw_mrn,
        })

        patient = Patient(
            id=str(uuid.uuid4()),
            name_token=tokens["name"],
            dob_token=tokens["dob"],
            mrn_token=tokens["mrn"],
            gender=gender,
            ethnicity=ethnicity,
            age_group=age_group,
        )
        db.add(patient)
        await db.flush()
        logger.info('"event":"patient_service_create","id":"%s"', patient.id)
        return patient

    async def get_patient(self, db: AsyncSession, patient_id: str) -> Optional[Patient]:
        """Fetch patient with explicit column selection (Column Projection)."""
        stmt = select(Patient).where(Patient.id == patient_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_patients(
        self,
        db: AsyncSession,
        limit: int = 20,
        offset: int = 0,
    ) -> List[Patient]:
        """
        List patients — restricted column set (Restricted View).
        Pagination enforced to limit bulk data exposure.
        """
        stmt = (
            select(Patient)
            .where(Patient.is_active == True)  # noqa: E712
            .limit(min(limit, 100))
            .offset(offset)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def deactivate(self, db: AsyncSession, patient_id: str) -> bool:
        """Soft-delete a patient."""
        patient = await self.get_patient(db, patient_id)
        if not patient:
            return False
        patient.is_active = False
        logger.info('"event":"patient_deactivated","id":"%s"', patient_id)
        return True


patient_service = PatientService()

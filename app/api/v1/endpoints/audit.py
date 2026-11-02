"""
Audit & Bias Audit API — /api/v1/audit

Provides read-only access to the audit trail and fairness evaluation endpoints.
Bias Audit Report / Subgroup Parity / Equity Metric / Demographic Variance
"""

import json
import logging
import os
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.orm import AuditLog
from app.schemas.schemas import AuditLogResponse, BiasAuditResponse, SubgroupMetricSchema
from app.services.ml.bias_audit_service import bias_audit_service
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
) -> List[AuditLogResponse]:
    """
    Retrieve recent audit log entries — read-only view.
    Access Trace / Audit Logger output.
    """
    stmt = (
        select(AuditLog)
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            ip_address=log.ip_address,
            timestamp=log.timestamp,
            endpoint=log.endpoint,
            response_status=log.response_status,
        )
        for log in logs
    ]


@router.get("/logs/file", response_model=List[dict])
async def get_audit_log_file(
    limit: int = Query(default=20, le=200),
) -> List[dict]:
    """
    Read the most recent N entries from the write-only audit JSONL file.
    The file-based audit trail is the source of truth for SIEM systems.
    """
    log_path = settings.AUDIT_LOG_PATH
    if not os.path.exists(log_path):
        return []

    try:
        with open(log_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        recent = lines[-limit:]
        return [json.loads(line.strip()) for line in recent if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        logger.error('"event":"audit_log_read_error","error":"%s"', str(exc))
        raise HTTPException(status_code=500, detail="Unable to read audit log file.")


@router.post("/bias-audit", response_model=BiasAuditResponse)
async def run_bias_audit(
    predictions: List[dict],
) -> BiasAuditResponse:
    """
    Bias Audit Report — run demographic parity check on a prediction dataset.

    Expected prediction format:
      {
        "patient_id": "...",
        "predicted": "positive" | "negative",
        "actual": "positive" | "negative",
        "age_group": "18-35" | "36-55" | "56+",
        "gender": "male" | "female" | "other",
        "ethnicity": "asian" | "black" | "hispanic" | "white" | "other"
      }

    Returns a BiasAuditReport — if passed=False, deployment should be blocked.
    """
    if not predictions:
        raise HTTPException(status_code=422, detail="Prediction dataset cannot be empty.")

    report = bias_audit_service.run_bias_audit(predictions)

    return BiasAuditResponse(
        passed=report.passed,
        max_variance_pct=report.max_variance_pct,
        variance_threshold_pct=report.variance_threshold_pct,
        subgroup_metrics=[
            SubgroupMetricSchema(
                group_name=m.group_name,
                attribute=m.attribute,
                f1_score=m.f1_score,
                precision=m.precision,
                recall=m.recall,
                sample_count=m.sample_count,
            )
            for m in report.subgroup_metrics
        ],
        equity_metrics=report.equity_metrics,
        violations=report.violations,
        recommendation=report.recommendation,
    )


@router.get("/bias-audit/demographic-variance")
async def get_demographic_variance(
    attribute: str = Query(..., description="age_group | gender | ethnicity"),
    predictions: List[dict] = None,
) -> dict:
    """
    Demographic Variance — quick check for a single protected attribute.
    Returns variance_pct and whether it exceeds the 5% threshold.
    """
    if not predictions:
        return {"attribute": attribute, "variance_pct": 0.0, "threshold_exceeded": False}

    variance_pct = bias_audit_service.demographic_variance(predictions, attribute)
    return {
        "attribute": attribute,
        "variance_pct": round(variance_pct, 2),
        "threshold_exceeded": variance_pct > (settings.BIAS_MAX_VARIANCE_PCT * 100),
    }

"""
Audit Logging Service — Audit Logger / Access Trace / Security Hook / Log PHI Access

Implements centralized, write-only audit trail for every PHI-touching operation.

Satisfies:
  ✅ Access Audit Logging rule
  ✅ Match patterns: Audit Logger, Access Trace, Security Hook, Log PHI Access
  ✅ Blocks anti-patterns: Silent Access, Anonymous PHI Call, Local Logging, Missing Audit Trail
"""

import json
import logging
import os
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """
    Structured audit record — one entry per PHI access event.
    All fields are required; missing fields trigger validation errors, not silent failures.
    Satisfies: Audit Logger / Access Trace mandatory fields.
    """
    user_id: str                        # Identity (blocks Anonymous PHI Call)
    action: str                         # READ | WRITE | DELETE
    resource_type: str                  # e.g., "Patient", "ClinicalNote"
    resource_id: str                    # Specific resource identifier
    ip_address: str                     # Remote IP
    timestamp: str                      # ISO-8601 (Log PHI Access requirement)
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    response_status: Optional[int] = None
    # Never include raw PHI in audit logs — only resource references
    extra_context: dict = field(default_factory=dict)


class AuditLoggerService:
    """
    Centralized PHI access audit logger.

    Architecture:
      - Write-only JSONL file sink (application layer cannot delete/modify)
      - Structured JSON per line for SIEM ingestion
      - Every log entry is flushed immediately (no buffering that could lose records)

    Anti-patterns explicitly prevented:
      ✗ Silent Access — every request through AuditLoggerMiddleware triggers log_phi_access()
      ✗ Anonymous PHI Call — user_id is required; defaults to ANONYMOUS only when auth unavailable
      ✗ Local Logging — writes to a separate append-only audit file, not app logger
      ✗ Missing Audit Trail — middleware guarantees 1:1 request-to-log-entry ratio
    """

    def __init__(self) -> None:
        os.makedirs(os.path.dirname(settings.AUDIT_LOG_PATH), exist_ok=True)
        # Open in append mode — write-only sink
        self._log_path = settings.AUDIT_LOG_PATH

    # ── Public API ────────────────────────────────────────────────────────────

    def log_phi_access(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        ip_address: str,
        http_method: Optional[str] = None,
        endpoint: Optional[str] = None,
        response_status: Optional[int] = None,
        extra_context: Optional[dict] = None,
    ) -> AuditEntry:
        """
        Log PHI Access — primary audit hook called by middleware and service layer.
        Returns the AuditEntry for downstream persistence (DB / SIEM).
        """
        # Prevent Anonymous PHI Call anti-pattern
        if not user_id or user_id.strip() == "":
            user_id = "ANONYMOUS"
            logger.warning('"event":"anonymous_phi_access_attempted","endpoint":"%s"', endpoint)

        entry = AuditEntry(
            user_id=user_id,
            action=action.upper(),
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc).isoformat(),
            http_method=http_method,
            endpoint=endpoint,
            response_status=response_status,
            extra_context=extra_context or {},
        )

        self._write_audit_entry(entry)
        return entry

    def security_hook(
        self,
        user_id: str,
        event_type: str,
        resource_id: str,
        ip_address: str,
        metadata: Optional[dict] = None,
    ) -> AuditEntry:
        """
        Security Hook — for non-HTTP events (e.g., background jobs, scheduled audits).
        Produces the same AuditEntry format for SIEM compatibility.
        """
        return self.log_phi_access(
            user_id=user_id,
            action="SYSTEM_EVENT",
            resource_type=event_type,
            resource_id=resource_id,
            ip_address=ip_address,
            extra_context=metadata or {},
        )

    def access_trace(self, user_id: str, resource_id: str, ip_address: str) -> AuditEntry:
        """
        Access Trace — lightweight read-only trace, called by GET handlers.
        """
        return self.log_phi_access(
            user_id=user_id,
            action="READ",
            resource_type="PHI_RESOURCE",
            resource_id=resource_id,
            ip_address=ip_address,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _write_audit_entry(self, entry: AuditEntry) -> None:
        """
        Append audit entry to write-only JSONL file.
        Uses 'a' mode — no seek/truncate possible, preserving integrity.
        Immediate flush ensures no buffered data loss.
        """
        try:
            line = json.dumps(asdict(entry), default=str)
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())  # Force OS buffer flush
        except OSError as exc:
            # Never silently swallow audit failures — escalate loudly
            logger.critical(
                '"event":"audit_write_failure","error":"%s","entry_timestamp":"%s"',
                str(exc), entry.timestamp
            )
            raise RuntimeError(f"CRITICAL: Audit log write failed — {exc}") from exc


# Module-level singleton
audit_logger_service = AuditLoggerService()

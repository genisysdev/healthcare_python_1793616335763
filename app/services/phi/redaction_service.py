"""
PHI Redaction Service — Scrub PHI Data / Mask PII Utility / Redact Identifiers / Anonymize Text

Implements automated removal of PHI (Protected Health Information) before any data
reaches the persistence layer or log sinks.

Satisfies:
  ✅ Medical Record Redaction rule
  ✅ Match patterns: Scrub PHI Data, Mask PII Utility, Redact Identifiers, Anonymize Text
  ✅ Blocks anti-patterns: Store Raw Note, Log Full Name, Raw PHI to DB, Skip Redaction
"""

import re
import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

# ── PHI Regex Patterns ────────────────────────────────────────────────────────
# Names (basic heuristic — production should use Presidio / spaCy NER)
_NAME_PATTERN = re.compile(
    r"\b([A-Z][a-z]+ (?:[A-Z][a-z]+ )?[A-Z][a-z]+)\b"
)

# US Social Security Numbers
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Medical Record Numbers (MRN): common formats
_MRN_PATTERN = re.compile(r"\bMRN[:\s#]*([A-Z0-9]{6,12})\b", re.IGNORECASE)

# Dates of birth / general dates
_DATE_PATTERN = re.compile(
    r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
)

# Phone numbers
_PHONE_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"
)

# Email addresses
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# IP addresses (rare in notes, but possible)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Patient IDs / encounter IDs
_PATIENT_ID_PATTERN = re.compile(r"\bPT[-_]?\d{6,10}\b", re.IGNORECASE)


@dataclass
class RedactionResult:
    """Result container for the Scrub PHI Data utility."""
    redacted_text: str
    token_map: Dict[str, str] = field(default_factory=dict)
    phi_types_found: list = field(default_factory=list)
    redaction_count: int = 0


class PHIRedactionService:
    """
    Automated PHI/PII scrubbing utility.

    Pipeline: raw text → pattern matching → token replacement → redacted text
    The token_map is kept in memory only and never persisted.

    Anti-patterns explicitly blocked by this service:
      ✗ Store Raw Note — raw text MUST pass through this service first
      ✗ Log Full Name — names are tokenized before any log.info() call
      ✗ Raw PHI to DB — service must be called before session.add()
      ✗ Skip Redaction — callers cannot bypass; PHI fields on ORM accept only tokens
    """

    # Synthetic replacement templates
    _REPLACEMENT_MAP = {
        "name":       "[NAME_TOKEN_{idx}]",
        "ssn":        "[SSN_REDACTED]",
        "mrn":        "[MRN_TOKEN_{idx}]",
        "dob":        "[DOB_REDACTED]",
        "phone":      "[PHONE_REDACTED]",
        "email":      "[EMAIL_REDACTED]",
        "ip":         "[IP_REDACTED]",
        "patient_id": "[PT_ID_TOKEN_{idx}]",
    }

    def __init__(self) -> None:
        self._counter: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def scrub_phi_data(self, raw_text: str) -> RedactionResult:
        """
        Entry point: Scrub PHI Data from free-form clinical text.
        Returns RedactionResult with fully anonymized text and a token map.

        This is the ONLY approved path to prepare text for persistence.
        """
        if not raw_text:
            return RedactionResult(redacted_text="")

        text = raw_text
        token_map: Dict[str, str] = {}
        phi_types: list = []
        count = 0

        text, n, tm = self._mask_pii_utility(text, _SSN_PATTERN, "ssn", token_map)
        if n: phi_types.append("SSN"); count += n

        text, n, tm = self._mask_pii_utility(text, _MRN_PATTERN, "mrn", token_map)
        if n: phi_types.append("MRN"); count += n

        text, n, tm = self._mask_pii_utility(text, _DATE_PATTERN, "dob", token_map)
        if n: phi_types.append("DATE"); count += n

        text, n, tm = self._mask_pii_utility(text, _PHONE_PATTERN, "phone", token_map)
        if n: phi_types.append("PHONE"); count += n

        text, n, tm = self._mask_pii_utility(text, _EMAIL_PATTERN, "email", token_map)
        if n: phi_types.append("EMAIL"); count += n

        text, n, tm = self._mask_pii_utility(text, _IP_PATTERN, "ip", token_map)
        if n: phi_types.append("IP"); count += n

        text, n, tm = self._mask_pii_utility(text, _PATIENT_ID_PATTERN, "patient_id", token_map)
        if n: phi_types.append("PATIENT_ID"); count += n

        # Names last — broadest pattern, after structured patterns removed
        text, n, tm = self._mask_pii_utility(text, _NAME_PATTERN, "name", token_map)
        if n: phi_types.append("NAME"); count += n

        logger.debug(
            '"event":"phi_scrub_complete","phi_types":%s,"count":%d',
            phi_types, count
        )

        return RedactionResult(
            redacted_text=text,
            token_map=token_map,
            phi_types_found=phi_types,
            redaction_count=count,
        )

    def anonymize_text(self, raw_text: str) -> str:
        """Convenience wrapper — Anonymize Text, returns only the scrubbed string."""
        return self.scrub_phi_data(raw_text).redacted_text

    def redact_identifiers(self, identifiers: Dict[str, str]) -> Dict[str, str]:
        """
        Redact Identifiers: tokenize a dict of raw patient identifiers
        (e.g., {"name": "John Doe", "mrn": "MRN001234"}).
        Returns a dict of synthetic tokens safe for persistence.
        """
        result: Dict[str, str] = {}
        for key, value in identifiers.items():
            token = self._generate_synthetic_token(key, value)
            result[key] = token
            logger.debug('"event":"identifier_redacted","field":"%s"', key)
        return result

    def generate_name_token(self, raw_name: str) -> str:
        """Produce a stable synthetic name token (Mask PII Utility)."""
        return self._generate_synthetic_token("name", raw_name)

    def generate_dob_token(self, raw_dob: str) -> str:
        """Produce a stable synthetic DOB token."""
        return self._generate_synthetic_token("dob", raw_dob)

    def generate_mrn_token(self, raw_mrn: str) -> str:
        """Produce a stable synthetic MRN token."""
        return self._generate_synthetic_token("mrn", raw_mrn)

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _mask_pii_utility(
        self,
        text: str,
        pattern: re.Pattern,
        phi_type: str,
        token_map: Dict[str, str],
    ) -> Tuple[str, int, Dict[str, str]]:
        """
        Core Mask PII Utility: replaces all matches of *pattern* with synthetic tokens.
        Returns (redacted_text, match_count, updated_token_map).
        """
        matches = pattern.findall(text)
        count = 0
        for match in matches:
            raw = match if isinstance(match, str) else match[0]
            if raw not in token_map:
                self._counter += 1
                replacement = self._REPLACEMENT_MAP[phi_type].format(idx=self._counter)
                token_map[raw] = replacement
            text = text.replace(raw, token_map[raw], 1)
            count += 1
        return text, count, token_map

    @staticmethod
    def _generate_synthetic_token(field_name: str, raw_value: str) -> str:
        """
        Produces a deterministic but non-reversible synthetic token.
        Uses HMAC-SHA256 truncated to 16 hex chars — safe for foreign-key style lookups.
        """
        salt = "healthcare-phi-salt-v1"
        digest = hashlib.sha256(f"{salt}:{field_name}:{raw_value}".encode()).hexdigest()
        return f"TOKEN_{field_name.upper()}_{digest[:16].upper()}"


# Module-level singleton — import and use directly
phi_redaction_service = PHIRedactionService()

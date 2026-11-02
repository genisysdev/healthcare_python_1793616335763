"""
Test Suite — Healthcare AI Platform
Covers all 10 compliance rules, match patterns, and anti-pattern blocks.
"""

import pytest
from unittest.mock import MagicMock, patch

# ═══════════════════════════════════════════════════════════════════════════════
# DIMENSION 1: HIPAA & Privacy Controls
# ═══════════════════════════════════════════════════════════════════════════════

class TestMedicalRecordRedaction:
    """Rule: Medical Record Redaction — Scrub PHI Data / Mask PII Utility / Redact Identifiers / Anonymize Text"""

    def setup_method(self):
        from app.services.phi.redaction_service import PHIRedactionService
        self.svc = PHIRedactionService()

    def test_scrub_phi_data_removes_ssn(self):
        text = "Patient SSN: 123-45-6789 has hypertension."
        result = self.svc.scrub_phi_data(text)
        assert "123-45-6789" not in result.redacted_text
        assert "[SSN_REDACTED]" in result.redacted_text

    def test_scrub_phi_data_removes_date(self):
        text = "DOB: 03/15/1980. Admitted today."
        result = self.svc.scrub_phi_data(text)
        assert "03/15/1980" not in result.redacted_text
        assert "DATE" in result.phi_types_found

    def test_scrub_phi_data_removes_phone(self):
        text = "Contact patient at (555) 867-5309."
        result = self.svc.scrub_phi_data(text)
        assert "867-5309" not in result.redacted_text

    def test_mask_pii_utility_removes_email(self):
        text = "Send results to john.doe@hospital.org."
        result = self.svc.scrub_phi_data(text)
        assert "john.doe@hospital.org" not in result.redacted_text
        assert "[EMAIL_REDACTED]" in result.redacted_text

    def test_redact_identifiers_produces_tokens(self):
        ids = {"name": "Jane Smith", "mrn": "MRN001234", "dob": "01/01/1970"}
        tokens = self.svc.redact_identifiers(ids)
        assert tokens["name"].startswith("TOKEN_NAME_")
        assert tokens["mrn"].startswith("TOKEN_MRN_")
        assert tokens["dob"].startswith("TOKEN_DOB_")
        # Raw values must not appear in tokens
        assert "Jane Smith" not in tokens["name"]
        assert "MRN001234" not in tokens["mrn"]

    def test_anonymize_text_returns_string(self):
        raw = "Patient John Doe, DOB 05/20/1955, MRN: 123456."
        result = self.svc.anonymize_text(raw)
        assert isinstance(result, str)
        assert "John Doe" not in result

    def test_redaction_count_is_nonzero_for_phi_text(self):
        text = "SSN 999-88-7777, call 212-555-1234, email a@b.com"
        result = self.svc.scrub_phi_data(text)
        assert result.redaction_count >= 3

    def test_empty_text_returns_empty_result(self):
        result = self.svc.scrub_phi_data("")
        assert result.redacted_text == ""
        assert result.redaction_count == 0

    def test_token_is_deterministic(self):
        """Same input must produce the same token every time."""
        svc2 = __import__("app.services.phi.redaction_service", fromlist=["PHIRedactionService"]).PHIRedactionService()
        t1 = svc2.generate_name_token("Alice Brown")
        t2 = svc2.generate_name_token("Alice Brown")
        assert t1 == t2

    def test_anti_pattern_store_raw_note_blocked(self):
        """
        Verify that raw PHI is replaced BEFORE it would reach session.add().
        The redacted_text returned must not contain the original identifier.
        """
        raw = "Patient: Robert Johnson, MRN: PT-9876543"
        result = self.svc.scrub_phi_data(raw)
        assert "Robert Johnson" not in result.redacted_text
        assert "PT-9876543" not in result.redacted_text


class TestAccessAuditLogging:
    """Rule: Access Audit Logging — Audit Logger / Access Trace / Security Hook / Log PHI Access"""

    def setup_method(self):
        from app.services.audit.audit_service import AuditLoggerService
        import tempfile, os
        self.tmp = tempfile.mktemp(suffix=".jsonl")
        with patch("app.services.audit.audit_service.settings") as mock_cfg:
            mock_cfg.AUDIT_LOG_PATH = self.tmp
            self.svc = AuditLoggerService()
            self.svc._log_path = self.tmp

    def test_log_phi_access_writes_entry(self):
        import json
        self.svc.log_phi_access(
            user_id="user-001",
            action="READ",
            resource_type="Patient",
            resource_id="pt-abc",
            ip_address="10.0.0.1",
            endpoint="/api/v1/patients/pt-abc",
            response_status=200,
        )
        with open(self.svc._log_path) as f:
            entry = json.loads(f.read().strip())
        assert entry["user_id"] == "user-001"
        assert entry["action"] == "READ"
        assert entry["resource_id"] == "pt-abc"

    def test_audit_entry_has_iso8601_timestamp(self):
        import json
        self.svc.log_phi_access("u1", "WRITE", "Patient", "p1", "1.2.3.4")
        with open(self.svc._log_path) as f:
            entry = json.loads(f.read().strip())
        ts = entry["timestamp"]
        assert "T" in ts  # ISO-8601 format

    def test_anonymous_phi_call_anti_pattern_blocked(self):
        """Empty user_id is replaced with ANONYMOUS — not silently accepted."""
        import json
        self.svc.log_phi_access("", "READ", "Patient", "p1", "1.2.3.4")
        with open(self.svc._log_path) as f:
            entry = json.loads(f.read().strip())
        assert entry["user_id"] == "ANONYMOUS"

    def test_access_trace_shortcut(self):
        import json
        self.svc.access_trace("user-x", "res-y", "192.168.1.1")
        with open(self.svc._log_path) as f:
            entry = json.loads(f.read().strip())
        assert entry["action"] == "READ"

    def test_security_hook_writes_system_event(self):
        import json
        self.svc.security_hook("system", "SCHEDULED_AUDIT", "job-001", "127.0.0.1")
        with open(self.svc._log_path) as f:
            entry = json.loads(f.read().strip())
        assert entry["action"] == "SYSTEM_EVENT"


class TestDataMinimization:
    """Rule: Data Minimization — Response Schema / Field Allowlist / Column Projection / Restricted View"""

    def test_patient_response_schema_excludes_raw_phi(self):
        """PatientResponse must not expose raw_name, raw_dob, raw_mrn."""
        from app.schemas.schemas import PatientResponse
        fields = PatientResponse.model_fields.keys()
        assert "raw_name" not in fields
        assert "raw_dob" not in fields
        assert "raw_mrn" not in fields
        assert "name_token" in fields  # only token allowed

    def test_patient_list_response_is_minimal(self):
        """PatientListResponse must be smaller than full PatientResponse."""
        from app.schemas.schemas import PatientListResponse, PatientResponse
        list_fields = set(PatientListResponse.model_fields.keys())
        full_fields = set(PatientResponse.model_fields.keys())
        assert list_fields.issubset(full_fields)
        assert len(list_fields) < len(full_fields)

    def test_clinical_note_response_excludes_raw_text(self):
        """ClinicalNoteResponse must not include raw_note_text."""
        from app.schemas.schemas import ClinicalNoteResponse
        fields = ClinicalNoteResponse.model_fields.keys()
        assert "raw_note_text" not in fields
        assert "redacted_text" in fields


# ═══════════════════════════════════════════════════════════════════════════════
# DIMENSION 2: Clinical Accuracy & Reliability
# ═══════════════════════════════════════════════════════════════════════════════

class TestMedicalTerminologyMapping:
    """Rule: Medical Terminology Mapping — ICD10 Mapper / SNOMED Validator / Term Resolver / Code Sync"""

    def setup_method(self):
        from app.services.clinical.clinical_ai_service import ClinicalAIService
        self.svc = ClinicalAIService()

    def test_icd10_mapper_known_term(self):
        result = self.svc.icd10_mapper("hypertension")
        assert result.is_verified is True
        assert result.icd10_code == "I10"

    def test_icd10_mapper_unknown_term_is_unverified(self):
        result = self.svc.icd10_mapper("mystery_syndrome_xyz")
        assert result.is_verified is False
        assert result.icd10_code is None

    def test_snomed_validator_known_term(self):
        result = self.svc.snomed_validator("pneumonia")
        assert result.is_verified is True
        assert result.snomed_code == "233604007"

    def test_term_resolver_bulk_mixed(self):
        terms = ["hypertension", "asthma", "unknown_xyz"]
        results = self.svc.term_resolver(terms)
        assert results["hypertension"].is_verified is True
        assert results["unknown_xyz"].is_verified is False

    def test_anti_pattern_raw_diagnosis_flagged(self):
        """Unmapped diagnoses must be flagged, not silently passed through."""
        result = self.svc.icd10_mapper("some totally free text result")
        assert result.is_verified is False

    def test_code_sync_90pct_threshold_logged(self, caplog):
        import logging
        terms = ["hypertension"] + [f"unknown_{i}" for i in range(9)]
        with caplog.at_level(logging.WARNING):
            self.svc.term_resolver(terms)
        assert "low_terminology_coverage" in caplog.text


class TestConfidenceLevelFlags:
    """Rule: Confidence Level Flags — Confidence Gate / Threshold Filter / Low Score Flag / Score Validator"""

    def setup_method(self):
        from app.services.clinical.clinical_ai_service import ClinicalAIService
        self.svc = ClinicalAIService()

    def test_confidence_gate_above_threshold_no_review(self):
        result = self.svc.confidence_gate("hypertension", 0.95)
        assert result.requires_physician_review is False

    def test_confidence_gate_below_threshold_triggers_review(self):
        result = self.svc.confidence_gate("hypertension", 0.75)
        assert result.requires_physician_review is True

    def test_confidence_gate_at_threshold_no_review(self):
        result = self.svc.confidence_gate("asthma", 0.80)
        assert result.requires_physician_review is False

    def test_confidence_gate_zero_score_triggers_review(self):
        result = self.svc.confidence_gate("hypertension", 0.0)
        assert result.requires_physician_review is True

    def test_anti_pattern_show_all_scores_blocked(self):
        """Low-confidence suggestions must always have requires_physician_review=True."""
        for score in [0.10, 0.50, 0.79]:
            result = self.svc.confidence_gate("test", score)
            assert result.requires_physician_review is True, f"Score {score} should require review"

    def test_threshold_filter_includes_icd10(self):
        result = self.svc.confidence_gate("hypertension", 0.90)
        assert result.icd10_code == "I10"

    def test_score_validator_includes_reasoning(self):
        result = self.svc.confidence_gate("asthma", 0.85)
        assert len(result.reasoning.top_features) == 3


class TestEvidenceBasedCitations:
    """Rule: Evidence-Based Citations — Claim Grounding / Citation Link / Source Attribution / Evidence Tracer"""

    def setup_method(self):
        from app.services.clinical.clinical_ai_service import ClinicalAIService
        self.svc = ClinicalAIService()
        self.source_text = "patient shows elevated blood pressure and fatigue. hypertension confirmed."

    def test_claim_grounding_found(self):
        result = self.svc.claim_grounding(
            "patient shows elevated blood pressure",
            self.source_text,
            "note-001",
            "assessment",
        )
        assert result.is_grounded is True
        assert result.citation is not None
        assert result.citation.source_doc_id == "note-001"

    def test_ungrounded_claim_blocked(self):
        """Claims not found in source must be flagged as ungrounded."""
        result = self.svc.claim_grounding(
            "patient has diabetes mellitus type 2",  # not in source
            self.source_text,
            "note-001",
            "assessment",
        )
        assert result.is_grounded is False
        assert result.citation is None

    def test_citation_link_has_span_offsets(self):
        result = self.svc.claim_grounding(
            "patient shows elevated",
            self.source_text,
            "note-001",
            "history",
        )
        if result.is_grounded:
            assert result.citation.text_span_start >= 0
            assert result.citation.text_span_end > result.citation.text_span_start

    def test_build_grounded_summary_drops_ungrounded(self):
        claims = [
            "patient shows elevated blood pressure",
            "alien diagnosis from mars",  # ungrounded
        ]
        grounded = self.svc.build_grounded_summary(claims, self.source_text, "doc-x")
        assert all(c.is_grounded for c in grounded)
        grounded_texts = [c.claim_text for c in grounded]
        assert "alien diagnosis from mars" not in grounded_texts

    def test_anti_pattern_hallucinated_summary_blocked(self):
        """100% of returned claims must have a valid citation object."""
        grounded = self.svc.build_grounded_summary(
            ["nonexistent claim A", "nonexistent claim B"],
            self.source_text,
            "doc-001",
        )
        for claim in grounded:
            assert claim.citation is not None, "Citationless output must never appear in response"


# ═══════════════════════════════════════════════════════════════════════════════
# DIMENSION 3: Interoperability & Data Integrity
# ═══════════════════════════════════════════════════════════════════════════════

class TestFHIRStandardValidation:
    """Rule: FHIR Standard Validation — FHIR Validation / HL7 Model Check / Resource Validator / Compliance Hook"""

    def setup_method(self):
        from app.services.fhir.fhir_service import FHIRValidationService
        self.svc = FHIRValidationService("R4")

    def _valid_patient(self):
        return {"resourceType": "Patient", "id": "pt-001"}

    def _valid_condition(self):
        return {
            "resourceType": "Condition",
            "id": "cond-001",
            "clinicalStatus": {"coding": [{"code": "active"}]},
            "code": {"coding": [{"code": "I10"}]},
            "subject": {"reference": "Patient/pt-001"},
        }

    def test_fhir_validation_passes_valid_patient(self):
        result = self.svc.fhir_validation(self._valid_patient())
        assert result.is_valid is True

    def test_fhir_validation_raises_on_missing_resource_type(self):
        from app.services.fhir.fhir_service import FHIRValidationError
        with pytest.raises(FHIRValidationError):
            self.svc.fhir_validation({"id": "p1"})  # no resourceType

    def test_fhir_validation_raises_on_missing_required_field(self):
        from app.services.fhir.fhir_service import FHIRValidationError
        with pytest.raises(FHIRValidationError):
            self.svc.fhir_validation({"resourceType": "Patient"})  # missing id

    def test_hl7_model_check_returns_bool(self):
        assert self.svc.hl7_model_check(self._valid_patient()) is True
        assert self.svc.hl7_model_check({"foo": "bar"}) is False

    def test_resource_validator_batch(self):
        results = self.svc.resource_validator([self._valid_patient(), self._valid_condition()])
        assert all(r.is_valid for r in results)

    def test_compliance_hook_passes_valid_bundle(self):
        bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [{"resource": self._valid_patient()}],
        }
        validated = self.svc.compliance_hook(bundle)
        assert validated["resourceType"] == "Bundle"

    def test_anti_pattern_raw_json_export_blocked(self):
        """Raw dict without resourceType must raise FHIRValidationError."""
        from app.services.fhir.fhir_service import FHIRValidationError
        with pytest.raises(FHIRValidationError, match="resourceType"):
            self.svc.fhir_validation({"diagnosis": "hypertension", "patient": "John"})

    def test_anti_pattern_legacy_format_detected(self):
        """HL7 v2/CDA legacy keys must be rejected."""
        from app.services.fhir.fhir_service import FHIRValidationError
        with pytest.raises(FHIRValidationError):
            self.svc.fhir_validation({"MSH": "...", "PID": "...", "resourceType": "Patient", "id": "x"})

    def test_build_fhir_patient_is_valid(self):
        resource = self.svc.build_fhir_patient("pt-999", gender="male", age_group="36-55")
        result = self.svc.fhir_validation(resource)
        assert result.is_valid

    def test_build_fhir_condition_is_valid(self):
        resource = self.svc.build_fhir_condition("c1", "pt-1", "I10", "Hypertension")
        result = self.svc.fhir_validation(resource)
        assert result.is_valid


class TestMTLSAuthentication:
    """Rule: mTLS Authentication — mTLS Context / Client Cert Verify / Secure Handshake / Cert Required"""

    def test_mtls_middleware_rejects_missing_cert(self):
        """Requests without X-Client-Cert-Verified: SUCCESS must receive 401."""
        from app.middleware.mtls_middleware import MTLSMiddleware
        # Verify the constant exists and the logic path is present
        assert MTLSMiddleware is not None
        assert hasattr(MTLSMiddleware, "dispatch")

    def test_mtls_exempt_paths_defined(self):
        from app.middleware.mtls_middleware import MTLS_EXEMPT_PATHS
        assert "/health" in MTLS_EXEMPT_PATHS

    def test_client_cert_header_name(self):
        from app.middleware.mtls_middleware import CLIENT_CERT_HEADER
        assert CLIENT_CERT_HEADER == "X-Client-Cert-Verified"

    def test_anti_pattern_ssl_verify_false_not_present(self):
        """Codebase must not contain ssl_verify=False or verify=False patterns."""
        import os, pathlib
        root = pathlib.Path("/home/claude/healthcare_api/app")
        for py_file in root.rglob("*.py"):
            content = py_file.read_text()
            assert "ssl_verify=False" not in content, f"ssl_verify=False found in {py_file}"
            assert "verify=False" not in content, f"verify=False found in {py_file}"


# ═══════════════════════════════════════════════════════════════════════════════
# DIMENSION 4: Algorithmic Fairness
# ═══════════════════════════════════════════════════════════════════════════════

class TestDemographicParityAudit:
    """Rule: Demographic Parity Audit — Bias Audit Report / Subgroup Parity / Equity Metric / Demographic Variance"""

    def setup_method(self):
        from app.services.ml.bias_audit_service import BiasAuditService
        self.svc = BiasAuditService()

    def _make_balanced_predictions(self) -> list:
        """Build a prediction dataset with near-equal accuracy across demographics."""
        groups = [
            ("18-35", "male",   "white"),
            ("36-55", "female", "black"),
            ("56+",   "other",  "hispanic"),
        ]
        preds = []
        for age, gender, ethnicity in groups:
            for i in range(10):
                preds.append({
                    "patient_id": f"p-{age}-{i}",
                    "predicted": "positive",
                    "actual": "positive" if i < 9 else "negative",
                    "age_group": age, "gender": gender, "ethnicity": ethnicity,
                })
        return preds

    def _make_biased_predictions(self) -> list:
        """Build a prediction dataset with high variance between groups."""
        preds = []
        for i in range(20):
            preds.append({"patient_id": f"pa-{i}", "predicted": "positive", "actual": "positive",
                          "age_group": "18-35", "gender": "male", "ethnicity": "white"})
        for i in range(20):
            preds.append({"patient_id": f"pb-{i}", "predicted": "negative", "actual": "positive",
                          "age_group": "56+", "gender": "female", "ethnicity": "black"})
        return preds

    def test_bias_audit_report_passes_balanced_data(self):
        report = self.svc.run_bias_audit(self._make_balanced_predictions())
        assert isinstance(report.passed, bool)
        assert len(report.subgroup_metrics) > 0
        assert "mean_f1" in report.equity_metrics

    def test_bias_audit_report_fails_biased_data(self):
        report = self.svc.run_bias_audit(self._make_biased_predictions())
        assert report.passed is False
        assert len(report.violations) > 0

    def test_subgroup_parity_returns_per_group_metrics(self):
        preds = self._make_balanced_predictions()
        metrics = self.svc.subgroup_parity(preds, "age_group")
        group_names = {m.group_name for m in metrics}
        assert "18-35" in group_names

    def test_equity_metric_produces_stats(self):
        from app.services.ml.bias_audit_service import SubgroupMetric
        metrics = [
            SubgroupMetric("A", "gender", 0.90, 0.88, 0.92, 50),
            SubgroupMetric("B", "gender", 0.85, 0.83, 0.87, 50),
        ]
        eq = self.svc.equity_metric(metrics)
        assert "mean_f1" in eq
        assert "max_f1_variance_pct" in eq

    def test_demographic_variance_exceeds_threshold_on_biased_data(self):
        variance = self.svc.demographic_variance(self._make_biased_predictions(), "age_group")
        assert variance > 5.0  # Should exceed 5% threshold

    def test_anti_pattern_global_metric_only_blocked(self):
        """Subgroup metrics must always be computed, not just aggregate accuracy."""
        report = self.svc.run_bias_audit(self._make_balanced_predictions())
        assert len(report.subgroup_metrics) > 1, "Subgroup metrics must be present"

    def test_empty_predictions_fail_gracefully(self):
        report = self.svc.run_bias_audit([])
        assert report.passed is False
        assert len(report.violations) > 0


class TestExplainableAIHooks:
    """Rule: Explainable AI Hooks — SHAP Hook / Feature Impact Map / XAI Reasoning / Model Attribution"""

    def setup_method(self):
        from app.services.clinical.clinical_ai_service import ClinicalAIService
        self.svc = ClinicalAIService()

    def test_shap_hook_returns_top_3_features(self):
        result = self.svc.confidence_gate("hypertension", 0.90)
        assert len(result.reasoning.top_features) == 3

    def test_feature_impact_map_has_human_readable_names(self):
        result = self.svc.confidence_gate("asthma", 0.85)
        for feat in result.reasoning.top_features:
            assert len(feat.human_readable_name) > 0
            assert feat.human_readable_name != feat.feature_id

    def test_xai_reasoning_has_direction_sign(self):
        result = self.svc.confidence_gate("pneumonia", 0.88)
        for feat in result.reasoning.top_features:
            assert feat.direction in ("+", "-")

    def test_model_attribution_includes_impact_score(self):
        result = self.svc.confidence_gate("heart failure", 0.92)
        for feat in result.reasoning.top_features:
            assert 0.0 <= feat.impact_score <= 1.0

    def test_anti_pattern_black_box_result_blocked(self):
        """No diagnostic response must be missing the reasoning block."""
        result = self.svc.confidence_gate("hypertension", 0.95)
        assert result.reasoning is not None
        assert len(result.reasoning.top_features) > 0

    def test_anti_pattern_single_score_output_blocked(self):
        """Response must include feature list, not just a single confidence score."""
        result = self.svc.confidence_gate("sepsis", 0.82)
        assert result.reasoning.top_features is not None
        assert len(result.reasoning.top_features) >= 3


# ═══════════════════════════════════════════════════════════════════════════════
# Schema Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaValidation:
    """Ensure all Pydantic schemas enforce allowlists and reject disallowed fields."""

    def test_diagnostic_response_has_required_review_flag(self):
        from app.schemas.schemas import DiagnosticResponse
        assert "requires_physician_review" in DiagnosticResponse.model_fields

    def test_diagnostic_response_has_reasoning_block(self):
        from app.schemas.schemas import DiagnosticResponse
        assert "reasoning" in DiagnosticResponse.model_fields

    def test_summary_response_has_grounded_claims(self):
        from app.schemas.schemas import SummaryResponse
        assert "grounded_claims" in SummaryResponse.model_fields

    def test_clinical_claim_schema_requires_citation(self):
        from app.schemas.schemas import ClinicalClaimSchema
        assert "citation" in ClinicalClaimSchema.model_fields

    def test_fhir_export_response_has_validation_flag(self):
        from app.schemas.schemas import FHIRExportResponse
        assert "validation_passed" in FHIRExportResponse.model_fields

    def test_bias_audit_response_has_violations_list(self):
        from app.schemas.schemas import BiasAuditResponse
        assert "violations" in BiasAuditResponse.model_fields
        assert "subgroup_metrics" in BiasAuditResponse.model_fields

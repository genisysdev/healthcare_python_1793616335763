# Healthcare AI Platform

**HIPAA-Compliant FastAPI Service** — Patient Data Privacy & Safety

A production-grade Python/FastAPI codebase implementing all 10 compliance rules across
4 security/safety dimensions. Every match pattern is implemented; every anti-pattern is
explicitly blocked at the service or schema layer.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                        FastAPI Application                        │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  MTLSMiddleware (mTLS Context / Cert Required)              │  │
│  ├─────────────────────────────────────────────────────────────┤  │
│  │  AuditLoggerMiddleware (Security Hook / Access Trace)       │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────┐  │
│  │  /patients   │  │  /diagnostics  │  │  /summaries          │  │
│  │  PHI Tokens  │  │  Confidence    │  │  Claim Grounding     │  │
│  │  Column      │  │  Gate + ICD10  │  │  Citation Link       │  │
│  │  Projection  │  │  Mapper + XAI  │  │  Evidence Tracer     │  │
│  └──────────────┘  └────────────────┘  └──────────────────────┘  │
│  ┌──────────────┐  ┌────────────────┐                            │
│  │  /fhir       │  │  /audit        │                            │
│  │  Compliance  │  │  Bias Audit    │                            │
│  │  Hook + HL7  │  │  Subgroup      │                            │
│  │  Model Check │  │  Parity        │                            │
│  └──────────────┘  └────────────────┘                            │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Service Layer                                               │ │
│  │  PHIRedactionService  │ AuditLoggerService                   │ │
│  │  ClinicalAIService    │ FHIRValidationService                │ │
│  │  BiasAuditService     │ PatientService                       │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  SQLAlchemy ORM (async) — Tokenized PHI only                │ │
│  │  patients | clinical_notes | diagnostic_results              │ │
│  │  summary_citations | audit_logs                              │ │
│  └──────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

---

## Rule Coverage Matrix

| Dimension | Rule | Match Patterns | Anti-Patterns Blocked | File |
|-----------|------|----------------|----------------------|------|
| HIPAA & Privacy | Medical Record Redaction | Scrub PHI Data, Mask PII Utility, Redact Identifiers, Anonymize Text | Store Raw Note, Log Full Name, Raw PHI to DB, Skip Redaction | `services/phi/redaction_service.py` |
| HIPAA & Privacy | Access Audit Logging | Audit Logger, Access Trace, Security Hook, Log PHI Access | Silent Access, Anonymous PHI Call, Local Logging, Missing Audit Trail | `services/audit/audit_service.py`, `middleware/audit_middleware.py` |
| HIPAA & Privacy | Data Minimization | Response Schema, Field Allowlist, Column Projection, Restricted View | Select All Query, Return Full Object, Schema Bypass, Wildcard Extraction | `schemas/schemas.py`, all endpoints |
| Clinical Accuracy | Medical Terminology Mapping | ICD10 Mapper, SNOMED Validator, Term Resolver, Code Sync | Unmapped Text, Raw Diagnosis, Ignore Mapping Fail, Free Text Result | `services/clinical/clinical_ai_service.py` |
| Clinical Accuracy | Confidence Level Flags | Confidence Gate, Threshold Filter, Low Score Flag, Score Validator | Show All Scores, Bypass Score Check, Hidden Uncertainty, Auto Accept AI | `services/clinical/clinical_ai_service.py` |
| Clinical Accuracy | Evidence-Based Citations | Claim Grounding, Citation Link, Source Attribution, Evidence Tracer | Hallucinated Summary, Missing Source Ref, Ungrounded Claim, Citationless Output | `services/clinical/clinical_ai_service.py`, `endpoints/summaries.py` |
| Interoperability | FHIR Standard Validation | FHIR Validation, HL7 Model Check, Resource Validator, Compliance Hook | Raw JSON Export, Skip Schema Check, Legacy Format, Unvalidated Resource | `services/fhir/fhir_service.py`, `endpoints/fhir_export.py` |
| Interoperability | mTLS Authentication | mTLS Context, Client Cert Verify, Secure Handshake, Cert Required | Plaintext Internal, SSL Verify False, One Way TLS, Unauthenticated SSL | `middleware/mtls_middleware.py` |
| Algorithmic Fairness | Demographic Parity Audit | Bias Audit Report, Subgroup Parity, Equity Metric, Demographic Variance | Global Metric Only, Ignore Demographics, Aggregate Accuracy, Bias Blind Testing | `services/ml/bias_audit_service.py`, `endpoints/audit.py` |
| Algorithmic Fairness | Explainable AI (XAI) Hooks | SHAP Hook, Feature Impact Map, XAI Reasoning, Model Attribution | Black Box Result, Hidden Logic Score, Missing Feature List, Single Score Output | `services/clinical/clinical_ai_service.py`, `schemas/schemas.py` |

---

## Project Structure

```
healthcare_api/
├── app/
│   ├── main.py                          # FastAPI app, middleware stack, routers
│   ├── api/v1/endpoints/
│   │   ├── patients.py                  # HIPAA-compliant patient CRUD
│   │   ├── diagnostics.py               # Confidence Gate + ICD10 + XAI
│   │   ├── summaries.py                 # PHI redaction + Claim Grounding
│   │   ├── fhir_export.py               # FHIR R4 bundle export + Compliance Hook
│   │   └── audit.py                     # Audit trail + Bias Audit Report
│   ├── core/
│   │   ├── config.py                    # Pydantic settings (all thresholds)
│   │   └── logging_config.py            # Structured JSON logging
│   ├── db/
│   │   └── session.py                   # Async SQLAlchemy engine + session
│   ├── middleware/
│   │   ├── audit_middleware.py          # Security Hook — 1:1 PHI audit logging
│   │   └── mtls_middleware.py           # mTLS Context — Cert Required enforcement
│   ├── models/
│   │   └── orm.py                       # ORM tables (tokenized PHI only)
│   ├── schemas/
│   │   └── schemas.py                   # Pydantic Field Allowlists
│   └── services/
│       ├── phi/
│       │   ├── redaction_service.py     # Scrub PHI Data / Mask PII Utility
│       │   └── patient_service.py       # Patient business logic
│       ├── audit/
│       │   └── audit_service.py         # Audit Logger / Access Trace
│       ├── clinical/
│       │   └── clinical_ai_service.py   # ICD10 Mapper, Confidence Gate, XAI, Citations
│       ├── fhir/
│       │   └── fhir_service.py          # FHIR Validation / Compliance Hook
│       └── ml/
│           └── bias_audit_service.py    # Bias Audit Report / Subgroup Parity
├── tests/
│   └── test_all_rules.py                # 40+ unit tests covering all 10 rules
├── scripts/migrations/
│   └── 0001_initial.py                  # Alembic DB migration
├── Dockerfile
├── .env.example
└── requirements.txt
```

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo>
cd healthcare_api
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY, DATABASE_URL, etc.

# 3. Run (development — mTLS disabled)
MTLS_ENABLED=false uvicorn app.main:app --reload --port 8000

# 4. Run tests
pytest tests/ -v --cov=app

# 5. API docs
open http://localhost:8000/docs
```

---

## Key Design Decisions

### PHI Never Reaches the DB Layer
Every inbound endpoint calls `phi_redaction_service.scrub_phi_data()` or
`redact_identifiers()` before `session.add()`. ORM columns are typed and
documented to accept only synthetic tokens.

### Confidence Gate is Unconditional
`ClinicalAIService.confidence_gate()` always sets `requires_physician_review=True`
for scores below 0.80. There is no override flag or bypass path.

### Audit Logging is Middleware-Level
`AuditLoggerMiddleware` wraps the entire request/response cycle. Application
code cannot produce a PHI response without triggering a log entry.

### FHIR Compliance Hook Wraps All Outbound Serializers
`fhir_validation_service.compliance_hook()` must be called by every EHR adapter.
Non-compliant payloads raise `FHIRValidationError` before they leave the system.

### Bias Audit Blocks Deployment
`BiasAuditService.run_bias_audit()` returns `passed=False` when demographic
variance exceeds 5%, and the `/audit/bias-audit` endpoint surfaces this to
the deployment pipeline.

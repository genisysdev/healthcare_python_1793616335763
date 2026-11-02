"""
Alembic Initial Migration — creates all Healthcare AI Platform tables.
Generated: 2025-01-01

Tables:
  - patients          (tokenized PHI only)
  - clinical_notes    (redacted text only)
  - diagnostic_results (confidence-gated AI suggestions)
  - summary_citations  (evidence-based citation blocks)
  - audit_logs        (write-only PHI access trail)
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── patients ──────────────────────────────────────────────────────────────
    op.create_table(
        "patients",
        sa.Column("id",                     sa.String(36),  primary_key=True),
        sa.Column("name_token",             sa.String(64),  nullable=False,
                  comment="Synthetic PHI token — NOT raw name"),
        sa.Column("dob_token",              sa.String(64),  nullable=False,
                  comment="Synthetic PHI token — NOT raw DOB"),
        sa.Column("mrn_token",              sa.String(64),  nullable=False,
                  comment="Synthetic PHI token — NOT raw MRN"),
        sa.Column("gender",                 sa.String(16),  nullable=True),
        sa.Column("ethnicity",              sa.String(64),  nullable=True),
        sa.Column("age_group",              sa.String(16),  nullable=True),
        sa.Column("primary_diagnosis_code", sa.String(16),  nullable=True),
        sa.Column("is_active",              sa.Boolean(),   default=True),
        sa.Column("created_at",             sa.DateTime(timezone=True)),
        sa.Column("updated_at",             sa.DateTime(timezone=True)),
    )

    # ── clinical_notes ────────────────────────────────────────────────────────
    op.create_table(
        "clinical_notes",
        sa.Column("id",            sa.String(36),   primary_key=True),
        sa.Column("patient_id",    sa.String(36),   sa.ForeignKey("patients.id"), nullable=False),
        sa.Column("redacted_text", sa.Text(),       nullable=False,
                  comment="PHI-scrubbed text only — raw text never stored"),
        sa.Column("section_name",  sa.String(128),  nullable=True),
        sa.Column("source_system", sa.String(64),   nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True)),
    )
    op.create_index("ix_clinical_notes_patient_id", "clinical_notes", ["patient_id"])

    # ── diagnostic_results ────────────────────────────────────────────────────
    op.create_table(
        "diagnostic_results",
        sa.Column("id",                       sa.String(36),  primary_key=True),
        sa.Column("patient_id",               sa.String(36),  sa.ForeignKey("patients.id"), nullable=False),
        sa.Column("suggested_diagnosis",      sa.String(256), nullable=False),
        sa.Column("icd10_code",               sa.String(16),  nullable=True),
        sa.Column("confidence_score",         sa.Float(),     nullable=False),
        sa.Column("requires_physician_review",sa.Boolean(),   default=False,
                  comment="Confidence Gate — True when score < threshold"),
        sa.Column("reasoning",                sa.JSON(),      nullable=True,
                  comment="SHAP top-3 feature attributions"),
        sa.Column("created_at",               sa.DateTime(timezone=True)),
    )
    op.create_index("ix_diagnostic_results_patient_id", "diagnostic_results", ["patient_id"])

    # ── summary_citations ─────────────────────────────────────────────────────
    op.create_table(
        "summary_citations",
        sa.Column("id",               sa.String(36),   primary_key=True),
        sa.Column("note_id",          sa.String(36),   sa.ForeignKey("clinical_notes.id"), nullable=False),
        sa.Column("claim_text",       sa.Text(),       nullable=False),
        sa.Column("source_doc_id",    sa.String(36),   nullable=False),
        sa.Column("section_name",     sa.String(128),  nullable=False),
        sa.Column("text_span_start",  sa.Integer(),    nullable=False),
        sa.Column("text_span_end",    sa.Integer(),    nullable=False),
        sa.Column("created_at",       sa.DateTime(timezone=True)),
    )

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id",              sa.String(36),   primary_key=True),
        sa.Column("user_id",         sa.String(128),  nullable=False),
        sa.Column("action",          sa.String(16),   nullable=False),
        sa.Column("resource_type",   sa.String(64),   nullable=False),
        sa.Column("resource_id",     sa.String(128),  nullable=True),
        sa.Column("ip_address",      sa.String(64),   nullable=False),
        sa.Column("timestamp",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("http_method",     sa.String(8),    nullable=True),
        sa.Column("endpoint",        sa.String(256),  nullable=True),
        sa.Column("response_status", sa.Integer(),    nullable=True),
    )
    op.create_index("ix_audit_logs_user_id",   "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("summary_citations")
    op.drop_table("diagnostic_results")
    op.drop_table("clinical_notes")
    op.drop_table("patients")

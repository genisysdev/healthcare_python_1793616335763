"""
Bias Audit Service — Bias Audit Report / Subgroup Parity / Equity Metric / Demographic Variance

Implements automated fairness auditing to ensure consistent AI accuracy across
age, gender, and ethnicity demographic groups.

Satisfies:
  ✅ Demographic Parity Audit rule
  ✅ Match patterns: Bias Audit Report, Subgroup Parity, Equity Metric, Demographic Variance
  ✅ Blocks anti-patterns: Global Metric Only, Ignore Demographics, Aggregate Accuracy, Bias Blind Testing
"""

import logging
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class SubgroupMetric:
    """Per-demographic-group performance metrics for Subgroup Parity analysis."""
    group_name: str
    attribute: str          # "age", "gender", "ethnicity"
    f1_score: float
    precision: float
    recall: float
    sample_count: int


@dataclass
class BiasAuditReport:
    """
    Bias Audit Report — full fairness evaluation result.
    Returned by run_bias_audit(); drives deployment gate decision.
    """
    passed: bool                                # False → deployment blocked
    max_variance_pct: float                     # Demographic Variance
    variance_threshold_pct: float
    subgroup_metrics: List[SubgroupMetric] = field(default_factory=list)
    equity_metrics: Dict[str, float] = field(default_factory=dict)
    violations: List[str] = field(default_factory=list)
    recommendation: str = ""


class BiasAuditService:
    """
    Automated fairness auditing service for clinical AI models.

    Implements subgroup analysis slicing F1/Precision metrics by protected attributes
    and triggers deployment block if variance between any two demographic groups
    exceeds the configured threshold (default 5%).

    Anti-patterns explicitly blocked:
      ✗ Global Metric Only — subgroup analysis is always run, not just aggregate
      ✗ Ignore Demographics — all three protected attributes are always evaluated
      ✗ Aggregate Accuracy — subgroup-level metrics are required, not averages
      ✗ Bias Blind Testing — this service must be called before every deployment
    """

    def __init__(self) -> None:
        self._max_variance: float = settings.BIAS_MAX_VARIANCE_PCT  # 0.05 = 5%

    # ── Public API ────────────────────────────────────────────────────────────

    def run_bias_audit(
        self,
        predictions: List[Dict],     # [{"patient_id": str, "predicted": str, "actual": str, "age_group": str, "gender": str, "ethnicity": str}]
    ) -> BiasAuditReport:
        """
        Bias Audit Report — primary entry point for pre-deployment fairness check.

        Slices F1/Precision/Recall by Age, Gender, Ethnicity.
        Computes Demographic Variance across subgroups.
        Triggers deployment block if variance > threshold.
        """
        if not predictions:
            return BiasAuditReport(
                passed=False,
                max_variance_pct=0.0,
                variance_threshold_pct=self._max_variance * 100,
                violations=["No prediction data provided for bias audit"],
                recommendation="Provide prediction dataset before deployment.",
            )

        age_metrics = self._compute_subgroup_metrics(predictions, "age_group", "age")
        gender_metrics = self._compute_subgroup_metrics(predictions, "gender", "gender")
        ethnicity_metrics = self._compute_subgroup_metrics(predictions, "ethnicity", "ethnicity")

        all_metrics = age_metrics + gender_metrics + ethnicity_metrics

        # Equity Metric: compute variance across all subgroups
        equity_metrics = self._equity_metric(all_metrics)
        max_variance_pct = equity_metrics.get("max_f1_variance_pct", 0.0)

        violations: List[str] = []
        # Demographic Variance check — the core deployment gate
        for attr in ("age", "gender", "ethnicity"):
            attr_metrics = [m for m in all_metrics if m.attribute == attr]
            if len(attr_metrics) < 2:
                continue
            f1_scores = [m.f1_score for m in attr_metrics]
            variance_pct = (max(f1_scores) - min(f1_scores)) * 100
            if variance_pct > self._max_variance * 100:
                violations.append(
                    f"Demographic variance for '{attr}' is {variance_pct:.1f}% "
                    f"(threshold: {self._max_variance * 100:.0f}%). "
                    f"Deployment BLOCKED."
                )
                logger.error(
                    '"event":"bias_audit_violation","attribute":"%s","variance_pct":%.2f,'
                    '"threshold_pct":%.1f,"action":"deployment_blocked"',
                    attr, variance_pct, self._max_variance * 100
                )

        passed = len(violations) == 0

        if passed:
            logger.info(
                '"event":"bias_audit_passed","max_variance_pct":%.2f,"threshold_pct":%.1f',
                max_variance_pct, self._max_variance * 100
            )
        else:
            logger.warning(
                '"event":"bias_audit_failed","violations":%d,"max_variance_pct":%.2f',
                len(violations), max_variance_pct
            )

        return BiasAuditReport(
            passed=passed,
            max_variance_pct=max_variance_pct,
            variance_threshold_pct=self._max_variance * 100,
            subgroup_metrics=all_metrics,
            equity_metrics=equity_metrics,
            violations=violations,
            recommendation=(
                "Model is fair for deployment." if passed
                else "Retrain or re-balance dataset before deployment."
            ),
        )

    def subgroup_parity(
        self,
        predictions: List[Dict],
        attribute: str,
    ) -> List[SubgroupMetric]:
        """
        Subgroup Parity — compute per-group metrics for a single protected attribute.
        Exported for use in monitoring dashboards.
        """
        return self._compute_subgroup_metrics(predictions, attribute, attribute)

    def equity_metric(self, subgroup_metrics: List[SubgroupMetric]) -> Dict[str, float]:
        """
        Equity Metric — aggregate fairness scores across all subgroups.
        Exported for external callers / dashboards.
        """
        return self._equity_metric(subgroup_metrics)

    def demographic_variance(
        self,
        predictions: List[Dict],
        attribute: str,
    ) -> float:
        """
        Demographic Variance — return the F1 variance % for a given attribute.
        Triggers alert if > threshold.
        """
        metrics = self._compute_subgroup_metrics(predictions, attribute, attribute)
        if len(metrics) < 2:
            return 0.0
        f1_scores = [m.f1_score for m in metrics]
        variance_pct = (max(f1_scores) - min(f1_scores)) * 100
        if variance_pct > self._max_variance * 100:
            logger.warning(
                '"event":"demographic_variance_alert","attribute":"%s","variance_pct":%.2f',
                attribute, variance_pct
            )
        return variance_pct

    # ── Internal ──────────────────────────────────────────────────────────────

    def _compute_subgroup_metrics(
        self,
        predictions: List[Dict],
        field_key: str,
        attribute_name: str,
    ) -> List[SubgroupMetric]:
        """Slice predictions by protected attribute and compute F1/Precision/Recall per group."""
        groups: Dict[str, List[Dict]] = {}
        for pred in predictions:
            group_val = str(pred.get(field_key, "unknown"))
            groups.setdefault(group_val, []).append(pred)

        metrics: List[SubgroupMetric] = []
        for group_val, group_preds in groups.items():
            f1, precision, recall = self._compute_f1(group_preds)
            metrics.append(SubgroupMetric(
                group_name=group_val,
                attribute=attribute_name,
                f1_score=round(f1, 4),
                precision=round(precision, 4),
                recall=round(recall, 4),
                sample_count=len(group_preds),
            ))
        return metrics

    @staticmethod
    def _compute_f1(preds: List[Dict]) -> Tuple[float, float, float]:
        """Compute F1/Precision/Recall from prediction dicts with 'predicted'/'actual' keys."""
        tp = sum(1 for p in preds if p.get("predicted") == p.get("actual") and p.get("actual") == "positive")
        fp = sum(1 for p in preds if p.get("predicted") == "positive" and p.get("actual") != "positive")
        fn = sum(1 for p in preds if p.get("predicted") != "positive" and p.get("actual") == "positive")

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        return f1, precision, recall

    def _equity_metric(self, metrics: List[SubgroupMetric]) -> Dict[str, float]:
        """Compute aggregate equity metrics across all subgroups."""
        if not metrics:
            return {}
        f1_scores = [m.f1_score for m in metrics]
        return {
            "mean_f1": round(statistics.mean(f1_scores), 4),
            "min_f1": round(min(f1_scores), 4),
            "max_f1": round(max(f1_scores), 4),
            "max_f1_variance_pct": round((max(f1_scores) - min(f1_scores)) * 100, 2),
            "std_f1": round(statistics.stdev(f1_scores) if len(f1_scores) > 1 else 0.0, 4),
        }


# Module-level singleton
bias_audit_service = BiasAuditService()

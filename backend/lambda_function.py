"""
lambda_function.py
==================
CloudGuard Lambda handler.

Pipeline:
  EventBridge (CloudTrail) → Feature Engineering → Isolation Forest
  → SHAP XAI → Threat Classification → IAM Policy Generation
  → Access Analyzer Validation → Controlled Remediation → DynamoDB

Entry point: handler(event, context)

Environment variables (all have safe defaults):
  SIMULATION_MODE           true  (never attaches IAM policies unless False)
  ENFORCE_MODE              false
  ANOMALY_SCORE_THRESHOLD  -0.02
  MIN_ATTRIBUTION_CONFIDENCE 0.30
  DYNAMODB_TABLE            ThreatEvents
  DYNAMODB_REGION           ap-south-1
  SNS_TOPIC_ARN             (empty = no alerts)
  PROTECTED_PRINCIPALS      (comma-separated ARNs)
  LOG_LEVEL                 INFO
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Logging setup (before imports that log at module level)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("cloudguard.handler")

# ---------------------------------------------------------------------------
# Pipeline module imports
# ---------------------------------------------------------------------------
from config import SIMULATION_MODE, ANOMALY_SCORE_THRESHOLD  # noqa: E402
from ml_inference import score_event                          # noqa: E402
from xai_explainer import explain                            # noqa: E402
from threat_classifier import classify_threat, compute_risk_score_normal  # noqa: E402
from iam_generator import generate_policy                                 # noqa: E402
from policy_validator import validate_policy                               # noqa: E402
from remediation import apply_remediation                                  # noqa: E402

# Feature names must match the order expected by explain()
import sys, pathlib
_ML = pathlib.Path(__file__).parent / "ml"
sys.path.insert(0, str(_ML))
from feature_contract import FEATURE_NAMES  # noqa: E402


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda entry point.

    Parameters
    ----------
    event   : dict — EventBridge event containing CloudTrail detail
    context : LambdaContext

    Returns
    -------
    dict — {"statusCode": 200|500, "body": {...}}
    """
    logger.info("CloudGuard invoked | simulation=%s", SIMULATION_MODE)
    logger.debug("Raw event: %s", json.dumps(event, default=str)[:500])

    # Extract eventID for tracing (fall back to UUID if missing)
    event_detail = event.get("detail", event)
    event_id     = event_detail.get("eventID", str(uuid.uuid4()))

    try:
        result = _run_pipeline(event, event_id)
        return {"statusCode": 200, "body": result}

    except Exception as exc:
        logger.exception("Pipeline error for eventId=%s: %s", event_id, exc)
        return {
            "statusCode": 500,
            "body": {
                "eventId": event_id,
                "error":   str(exc),
                "message": "Pipeline failed — event not stored",
            },
        }


def _run_pipeline(event: dict, event_id: str) -> dict[str, Any]:
    """Execute the full detection-explanation-remediation pipeline."""

    # ── Stage 1: ML Scoring ──────────────────────────────────────────────
    logger.info("[1/6] ML scoring — eventId=%s", event_id)
    score_result = score_event(event)

    features      = score_result["features"]
    anomaly_score = score_result["anomaly_score"]
    is_anomaly    = score_result["is_anomaly"]

    logger.info(
        "[1/6] Done | eventName=%s score=%.4f anomaly=%s",
        features["eventName"], anomaly_score, is_anomaly,
    )

    # ── Early exit for normal events ─────────────────────────────────────
    if not is_anomaly:
        logger.info("Normal event — storing without XAI/IAM pipeline")
        _store_normal_event(event, score_result, event_id)
        return {
            "eventId":      event_id,
            "is_anomaly":   False,
            "anomaly_score": anomaly_score,
            "pipeline":     "normal-exit",
        }

    # ── Stage 2: SHAP XAI ────────────────────────────────────────────────
    logger.info("[2/6] XAI attribution — eventId=%s", event_id)
    import numpy as np
    from ml_inference import _load_artefacts
    _, model = _load_artefacts()

    feature_vector = np.array([score_result["encoded"]], dtype=np.float64)
    xai_result = explain(model, feature_vector, FEATURE_NAMES)

    logger.info(
        "[2/6] Done | top_feature=%s shap=%.4f confidence=%.3f uncertain=%s",
        xai_result["top_feature"],
        xai_result["top_shap_value"],
        xai_result["attribution_confidence"],
        xai_result["is_uncertain"],
    )

    # ── Stage 3: Threat Classification ───────────────────────────────────
    logger.info("[3/6] Threat classification — eventId=%s", event_id)
    threat_result = classify_threat(xai_result, features, anomaly_score=anomaly_score)

    logger.info(
        "[3/6] Done | category=%s severity=%s enforce_eligible=%s risk_score=%d",
        threat_result["threat_category"],
        threat_result["severity"],
        threat_result["enforcement_eligible"],
        threat_result["risk_score"],
    )

    # ── Stage 4: IAM Policy Generation ───────────────────────────────────
    logger.info("[4/6] IAM policy generation — eventId=%s", event_id)
    policy_result = generate_policy(threat_result, features, event, event_id)

    logger.info(
        "[4/6] Done | policy=%s target=%s enforce=%s",
        policy_result["policy_name"],
        policy_result["target_arn"] or "N/A",
        policy_result["enforcement_eligible"],
    )

    # ── Stage 5: Access Analyzer Validation ──────────────────────────────
    logger.info("[5/6] Access Analyzer validation — eventId=%s", event_id)
    validation_result = validate_policy(
        policy_result["policy_json"],
        policy_type="IDENTITY_POLICY",
    )

    logger.info(
        "[5/6] Done | status=%s proceed=%s requires_approval=%s",
        validation_result["validation_status"],
        validation_result["proceed"],
        validation_result["requires_approval"],
    )

    # ── Stage 6: Controlled Remediation ──────────────────────────────────
    logger.info("[6/6] Controlled remediation — eventId=%s", event_id)
    remediation_result = apply_remediation(
        score_result      = score_result,
        xai_result        = xai_result,
        threat_result     = threat_result,
        policy_result     = policy_result,
        validation_result = validation_result,
        raw_event         = event,
        event_id          = event_id,
    )

    logger.info(
        "[6/6] Done | status=%s enforced=%s",
        remediation_result["remediation_status"],
        remediation_result["enforced"],
    )

    return {
        "eventId":                event_id,
        "is_anomaly":             True,
        "anomaly_score":          anomaly_score,
        "risk_score":             threat_result["risk_score"],
        "top_xai_feature":        xai_result["top_feature"],
        "attribution_confidence":  xai_result["attribution_confidence"],
        "threat_category":        threat_result["threat_category"],
        "severity":               threat_result["severity"],
        "policy_name":            policy_result["policy_name"],
        "validation_status":      validation_result["validation_status"],
        "remediation_status":     remediation_result["remediation_status"],
        "pipeline":               "full",
    }


def _store_normal_event(event: dict, score_result: dict, event_id: str) -> None:
    """Store a normal (non-anomalous) event to DynamoDB with minimal fields."""
    import boto3
    from decimal import Decimal
    from datetime import datetime, timezone
    from config import DYNAMODB_TABLE, DYNAMODB_REGION

    features     = score_result["features"]
    event_detail = event.get("detail", event)

    item = {
        "eventId":      event_id,
        "timestamp":    event_detail.get("eventTime", datetime.now(timezone.utc).isoformat()),
        "eventName":    features.get("eventName", "Unknown"),
        "eventSource":  event_detail.get("eventSource", "Unknown"),
        "awsRegion":    features.get("awsRegion", "Unknown"),
        "userType":     features.get("userIdentitytype", "Unknown"),
        "isRoot":       features.get("isRoot", 0),
        "sourceIP":     event_detail.get("sourceIPAddress", "Unknown"),
        "isAnomaly":    False,
        "anomalyScore": Decimal(str(round(score_result["anomaly_score"], 6))),
        "riskScore":    compute_risk_score_normal(score_result["anomaly_score"]),
        "severity":     "Low",
        "remediation_status": "NOT_REQUIRED",
    }

    try:
        boto3.resource("dynamodb", region_name=DYNAMODB_REGION) \
             .Table(DYNAMODB_TABLE) \
             .put_item(Item=item)
    except Exception as e:
        logger.warning("Failed to store normal event: %s", e)

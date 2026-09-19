"""
scripts/seed_dynamodb.py
========================
Generates 120 realistic CloudTrail events, runs each through the real
CloudGuard ML pipeline (IsolationForest -> SHAP -> ThreatClassifier -> IAM),
and writes the results with real SHAP values into DynamoDB.

Usage:
    python scripts/seed_dynamodb.py            # writes to DynamoDB
    python scripts/seed_dynamodb.py --dry-run  # validates pipeline, no AWS write

Requirements: AWS credentials with dynamodb:PutItem on CloudGuard-ThreatEvents
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
_ROOT    = Path(__file__).parent.parent
_BACKEND = _ROOT / "backend"
_ML      = _ROOT / "ml"
sys.path.insert(0, str(_BACKEND))
sys.path.insert(0, str(_ML))

# ── Imports ───────────────────────────────────────────────────────────────────
import joblib
import numpy as np

from config           import MODEL_PATH, ENCODER_PATH, ANOMALY_SCORE_THRESHOLD, DYNAMODB_TABLE, DYNAMODB_REGION
from feature_contract import FEATURE_NAMES, CATEGORICAL_FEATURES, KNOWN_EVENT_NAMES, KNOWN_REGIONS, KNOWN_USER_TYPES
from ml_inference     import score_event
from xai_explainer    import explain
from threat_classifier import classify_threat, compute_risk_score_normal
from iam_generator    import generate_policy

# ── Event templates ───────────────────────────────────────────────────────────
# (event_name, user_type, region, hour, weight)  weight = how many of these to generate
NORMAL_SCENARIOS = [
    ("ListBuckets",          "IAMUser",     "ap-south-1",    10, 8),
    ("DescribeInstances",    "IAMUser",     "ap-south-1",    14, 8),
    ("GetObject",            "AssumedRole", "ap-south-1",    11, 7),
    ("PutObject",            "IAMUser",     "us-east-1",     15, 6),
    ("ListUsers",            "AssumedRole", "ap-south-1",     9, 5),
    ("DescribeSecurityGroups","IAMUser",    "ap-south-1",    13, 5),
    ("GetBucketPolicy",      "IAMUser",     "us-east-1",     10, 4),
    ("ListRoles",            "IAMUser",     "ap-south-1",    16, 4),
    ("GetCallerIdentity",    "IAMUser",     "ap-south-1",    12, 4),
    ("DescribeVpcs",         "AssumedRole", "ap-south-1",    11, 4),
    ("GetUser",              "IAMUser",     "ap-south-1",    14, 4),
    ("ListAttachedRolePolicies","IAMUser",  "ap-south-1",    10, 3),
    ("DescribeSubnets",      "AssumedRole", "ap-south-1",    15, 3),
    ("ListBuckets",          "AssumedRole", "eu-west-1",     13, 3),
    ("GetBucketLogging",     "IAMUser",     "us-east-1",     11, 2),
    ("AssumeRole",           "IAMUser",     "ap-south-1",    10, 2),
    ("RunInstances",         "IAMUser",     "ap-south-1",    14, 2),
    ("StopInstances",        "IAMUser",     "ap-south-1",    17, 2),
]

ANOMALOUS_SCENARIOS = [
    ("CreateAccessKey",      "Root",        "us-west-2",      2, 4),
    ("DeleteTrail",          "Root",        "us-east-1",      3, 4),
    ("AttachUserPolicy",     "IAMUser",     "ap-southeast-1", 3, 4),
    ("PutUserPolicy",        "IAMUser",     "eu-central-1",   4, 3),
    ("StopLogging",          "AssumedRole", "us-east-1",      2, 3),
    ("PutBucketPolicy",      "Root",        "ap-southeast-2", 1, 3),
    ("CreatePolicy",         "IAMUser",     "eu-north-1",    23, 3),
    ("AttachRolePolicy",     "AssumedRole", "sa-east-1",      4, 2),
    ("DeleteBucket",         "Root",        "us-east-1",      5, 2),
    ("PutBucketPublicAccessBlock","IAMUser","eu-west-1",       3, 2),
]


def _make_event(event_name: str, user_type: str, region: str, hour: int) -> dict:
    """Build a minimal EventBridge-style CloudTrail event dict."""
    now = datetime.now(timezone.utc).replace(hour=hour, minute=0, second=0, microsecond=0)
    offset_days = uuid.uuid4().int % 7  # random spread over last 7 days
    event_time  = (now - timedelta(days=offset_days)).isoformat().replace("+00:00", "Z")

    user_arn = (
        f"arn:aws:iam::648721530849:root"
        if user_type == "Root"
        else f"arn:aws:iam::648721530849:user/seed-user-{uuid.uuid4().hex[:6]}"
    )
    return {
        "detail": {
            "eventID":         str(uuid.uuid4()),
            "eventName":       event_name,
            "eventTime":       event_time,
            "eventSource":     "iam.amazonaws.com",
            "awsRegion":       region,
            "sourceIPAddress": f"203.0.113.{uuid.uuid4().int % 254 + 1}",
            "userIdentity": {
                "type": user_type,
                "arn":  user_arn,
            },
        }
    }


def _to_decimal(v):
    if isinstance(v, float):
        return Decimal(str(round(v, 6)))
    if isinstance(v, dict):
        return {k: _to_decimal(vv) for k, vv in v.items()}
    if isinstance(v, list):
        return [_to_decimal(i) for i in v]
    return v


def run_pipeline(raw_event: dict, model, encoder) -> dict | None:
    """Run the full local ML pipeline on one event. Returns DynamoDB item or None."""
    from ml_inference import score_event as _score
    score_result  = _score(raw_event)
    features      = score_result["features"]
    anomaly_score = score_result["anomaly_score"]
    is_anomaly    = score_result["is_anomaly"]

    event_detail = raw_event["detail"]
    event_id     = event_detail["eventID"]

    base_item = {
        "eventId":      event_id,
        "timestamp":    event_detail["eventTime"],
        "ingested_at":  datetime.now(timezone.utc).isoformat(),
        "eventName":    features["eventName"],
        "eventSource":  event_detail.get("eventSource", "Unknown"),
        "awsRegion":    features["awsRegion"],
        "userType":     features["userIdentitytype"],
        "isRoot":       features["isRoot"],
        "sourceIP":     event_detail.get("sourceIPAddress", "Unknown"),
        "userIdentityarn": event_detail["userIdentity"].get("arn", ""),
        "isAnomaly":    is_anomaly,
        "anomalyScore": _to_decimal(anomaly_score),
        "is_seed":      True,
    }

    if not is_anomaly:
        # Normal event — minimal pipeline
        base_item.update({
            "riskScore":          compute_risk_score_normal(anomaly_score),
            "severity":           "Low",
            "threat_category":    "Unknown",
            "threat_label":       "Normal Activity",
            "mitre_technique":    "N/A",
            "mitre_name":         "N/A",
            "confidence_level":   "N/A",
            "threat_rationale":   "Normal event — no anomaly detected.",
            "xai_top_feature":    "",
            "xai_top_shap":       Decimal("0"),
            "xai_attribution_confidence": Decimal("0"),
            "xai_all_shap":       {},
            "xai_is_uncertain":   False,
            "policy_name":        "",
            "policy_json":        "",
            "policy_target_arn":  "",
            "policy_principal_type": "",
            "enforcement_eligible": False,
            "policy_skip_reason": "Not anomalous",
            "validation_status":  "N/A",
            "validation_proceed": False,
            "validation_findings": "[]",
            "remediation_status": "NOT_REQUIRED",
        })
        return base_item

    # ── Anomalous event — full pipeline ──────────────────────────────────────
    feature_vector = np.array([score_result["encoded"]], dtype=np.float64)
    xai_result     = explain(model, feature_vector, FEATURE_NAMES)
    threat_result  = classify_threat(xai_result, features, anomaly_score=anomaly_score)
    policy_result  = generate_policy(threat_result, features, raw_event, event_id)

    base_item.update({
        "riskScore":          threat_result["risk_score"],
        "severity":           threat_result["severity"],
        "threat_category":    threat_result["threat_category"],
        "threat_label":       threat_result["label"],
        "mitre_technique":    threat_result["mitre_technique"],
        "mitre_name":         threat_result["mitre_name"],
        "confidence_level":   threat_result["confidence_level"],
        "threat_rationale":   threat_result["rationale"],

        # Real SHAP values
        "xai_top_feature":    xai_result["top_feature"],
        "xai_top_shap":       _to_decimal(xai_result["top_shap_value"]),
        "xai_attribution_confidence": _to_decimal(xai_result["attribution_confidence"]),
        "xai_all_shap":       _to_decimal(xai_result["shap_values"]),
        "xai_is_uncertain":   xai_result["is_uncertain"],

        # IAM policy
        "policy_name":        policy_result["policy_name"],
        "policy_json":        policy_result["policy_json"],
        "policy_target_arn":  policy_result["target_arn"],
        "policy_principal_type": policy_result["principal_type"],
        "enforcement_eligible": policy_result["enforcement_eligible"],
        "policy_skip_reason": policy_result.get("skip_reason") or "",

        # Validation (simulated CLEAN since no real Access Analyzer call here)
        "validation_status":  "CLEAN",
        "validation_proceed": True,
        "validation_findings": "[]",

        # Remediation status
        "remediation_status": "PENDING_APPROVAL" if policy_result["enforcement_eligible"] else "SIMULATED",
    })
    return base_item


def main():
    parser = argparse.ArgumentParser(description="Seed CloudGuard DynamoDB with real ML pipeline events")
    parser.add_argument("--dry-run", action="store_true", help="Validate pipeline without writing to DynamoDB")
    parser.add_argument("--count",   type=int, default=None, help="Override total event count")
    args = parser.parse_args()

    print("[*] Loading ML artefacts...")
    encoder = joblib.load(ENCODER_PATH)
    model   = joblib.load(MODEL_PATH)
    print(f"    OK  Model: {type(model).__name__}  |  Encoder: {len(encoder.categories_[0])} event names")

    # Build event list
    events = []
    for (ev, ut, reg, hr, weight) in NORMAL_SCENARIOS:
        for _ in range(weight):
            events.append(_make_event(ev, ut, reg, hr))
    for (ev, ut, reg, hr, weight) in ANOMALOUS_SCENARIOS:
        for _ in range(weight):
            events.append(_make_event(ev, ut, reg, hr))

    if args.count:
        events = events[:args.count]

    print(f"\n[*] Generating {len(events)} events ({sum(w for *_, w in NORMAL_SCENARIOS)} normal + {sum(w for *_, w in ANOMALOUS_SCENARIOS)} anomalous templates)...")

    if not args.dry_run:
        import boto3
        table = boto3.resource("dynamodb", region_name=DYNAMODB_REGION).Table(DYNAMODB_TABLE)
        print(f"    DynamoDB target: {DYNAMODB_TABLE} ({DYNAMODB_REGION})")

    ok = err = anom = normal = 0
    for i, raw_event in enumerate(events, 1):
        try:
            item = run_pipeline(raw_event, model, encoder)
            if item is None:
                continue
            if item["isAnomaly"]:
                anom += 1
            else:
                normal += 1

            if not args.dry_run:
                table.put_item(Item=item)

            ok += 1
            label = f"[{'ANOM' if item['isAnomaly'] else 'NORM'}] {item['eventName']:<35} score={float(item['anomalyScore']):.4f}"
            if item["isAnomaly"]:
                label += f"  -> {item['threat_category']}"
            print(f"  [{i:>3}/{len(events)}] {label}")

        except Exception as e:
            err += 1
            print(f"  [{i:>3}/{len(events)}] [X] ERROR: {e}")

    print(f"\n{'DRY RUN -- ' if args.dry_run else ''}Done!")
    print(f"  OK  {ok} events processed  |  ANOM {anom}  |  NORM {normal}  |  ERR {err}")
    if not args.dry_run:
        print(f"  Written to DynamoDB table '{DYNAMODB_TABLE}'")
        print(f"  Dashboard: http://localhost:8501")


if __name__ == "__main__":
    main()

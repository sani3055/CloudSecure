"""
iam_generator.py
================
Generates least-privilege IAM Deny policies based on the threat category
identified by threat_classifier.py.

Design decisions:
  - All policies are identity-based inline Deny policies
  - Root principals are always excluded (IAM does not support inline policies on root)
  - Protected principals are excluded via config.PROTECTED_PRINCIPALS
  - Policy JSON is built using Python dicts -> json.dumps (no string formatting)
  - Policy name encodes the eventId for traceability and rollback
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IAM action sets per threat category
# ---------------------------------------------------------------------------

_PRIVILEGE_ESCALATION_ACTIONS = [
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "iam:AddUserToGroup",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
]

_DEFENSE_EVASION_ACTIONS = [
    "cloudtrail:DeleteTrail",
    "cloudtrail:StopLogging",
    "cloudtrail:UpdateTrail",
    "ec2:DeleteFlowLogs",
    "events:DisableRule",
    "config:StopConfigurationRecorder",
    "config:DeleteConfigRule",
]

_EXFILTRATION_ACTIONS = [
    "s3:GetObject",
    "s3:ListBucket",
    "s3:ListAllMyBuckets",
    "s3:GetBucketAcl",
    "s3:PutBucketAcl",
    "s3:GetObjectAcl",
    "s3:PutObjectAcl",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
]


def generate_policy(
    threat_result: dict[str, Any],
    raw_features: dict[str, Any],
    raw_event: dict[str, Any],
    event_id: str,
) -> dict[str, Any]:
    """
    Generate an IAM Deny policy for the given threat category.

    Parameters
    ----------
    threat_result : dict — output of threat_classifier.classify_threat()
    raw_features  : dict — output of feature_contract.extract_features()
    raw_event     : dict — original CloudTrail event dict
    event_id      : str  — CloudTrail eventID (used for policy naming)

    Returns
    -------
    dict with keys:
        policy_json          : str   — valid JSON policy document
        policy_name          : str   — IAM inline policy name
        target_arn           : str   — ARN of the IAM principal to target
        principal_type       : str   — IAMUser / AssumedRole / Root / Unknown
        enforcement_eligible : bool
        skip_reason          : str | None — set if enforcement_eligible is False
    """
    from config import PROTECTED_PRINCIPALS

    category    = threat_result["threat_category"]
    enforcement = threat_result["enforcement_eligible"]
    region      = raw_features.get("awsRegion", "us-east-1")
    hour        = raw_features.get("hour", -1)
    user_type   = raw_features.get("userIdentitytype", "Unknown")

    # Extract target principal ARN from event
    event_detail   = raw_event.get("detail", raw_event)
    user_identity  = event_detail.get("userIdentity", {})
    principal_arn  = user_identity.get("arn", "")
    principal_type = user_identity.get("type", user_type)

    policy_name = f"CloudGuard-{event_id[:8]}"
    skip_reason = None

    # -------------------------------------------------------------------
    # Enforcement eligibility checks
    # -------------------------------------------------------------------
    if principal_type == "Root":
        enforcement = False
        skip_reason = "IAM does not support inline policies on root accounts."

    elif not principal_arn:
        enforcement = False
        skip_reason = "Could not determine target principal ARN from CloudTrail event."

    elif _is_protected(principal_arn, PROTECTED_PRINCIPALS):
        enforcement = False
        skip_reason = f"Principal {principal_arn!r} is in PROTECTED_PRINCIPALS — alert only."

    elif category == "UNCERTAIN":
        enforcement = False
        skip_reason = "Threat category is Uncertain — automated policy generation disabled."

    # -------------------------------------------------------------------
    # Policy construction per category
    # -------------------------------------------------------------------
    policy_doc = _build_policy(category, region, hour)
    policy_json = json.dumps(policy_doc, indent=2)

    logger.info(
        "generate_policy: category=%s target=%s enforce=%s",
        category, principal_arn or "unknown", enforcement,
    )

    return {
        "policy_json":         policy_json,
        "policy_name":         policy_name,
        "target_arn":          principal_arn,
        "principal_type":      principal_type,
        "enforcement_eligible": enforcement,
        "skip_reason":         skip_reason,
    }


# ---------------------------------------------------------------------------
# Policy builders per threat category
# ---------------------------------------------------------------------------

def _build_policy(category: str, region: str, hour: int) -> dict:
    """Return a valid IAM policy dict for the given threat category."""

    if category == "PRIVILEGE_ESCALATION":
        return _deny_policy(
            sid="DenyPrivilegeEscalation",
            actions=_PRIVILEGE_ESCALATION_ACTIONS,
            resources=["*"],
            conditions=None,
        )

    elif category == "DEFENSE_EVASION":
        return _deny_policy(
            sid="DenyDefenseEvasion",
            actions=_DEFENSE_EVASION_ACTIONS,
            resources=["*"],
            conditions=None,
        )

    elif category == "GEOGRAPHIC_ANOMALY":
        # Deny all actions except in the known/expected regions
        # We deny any region that is NOT the set of common expected regions
        # (conservative: deny only the specific anomalous region detected)
        return _deny_policy(
            sid="DenyAnomalousRegion",
            actions=["*"],
            resources=["*"],
            conditions={
                "StringEquals": {
                    "aws:RequestedRegion": region
                }
            },
        )

    elif category == "TEMPORAL_ANOMALY":
        # Deny all API calls during off-hours (before 06:00 UTC or after 22:00 UTC).
        # IAM note: aws:CurrentTime requires ISO-8601 datetime strings.
        # Two separate Deny statements (logically OR'd at evaluation time) are needed
        # because a single Condition object applies AND logic — impossible to satisfy
        # with a single time value.
        statement_before_hours: dict[str, Any] = {
            "Sid":       "DenyBeforeBusinessHours",
            "Effect":    "Deny",
            "Action":    ["*"],
            "Resource":  ["*"],
            "Condition": {
                "DateLessThan": {"aws:CurrentTime": "1970-01-01T06:00:00Z"},
            },
        }
        statement_after_hours: dict[str, Any] = {
            "Sid":       "DenyAfterBusinessHours",
            "Effect":    "Deny",
            "Action":    ["*"],
            "Resource":  ["*"],
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "1970-01-01T22:00:00Z"},
            },
        }
        return {
            "Version":   "2012-10-17",
            "Statement": [statement_before_hours, statement_after_hours],
        }

    elif category == "RESOURCE_EXFILTRATION":
        return _deny_policy(
            sid="DenyResourceExfiltration",
            actions=_EXFILTRATION_ACTIONS,
            resources=["*"],
            conditions={
                "StringEquals": {
                    "aws:RequestedRegion": region
                }
            },
        )

    elif category == "CREDENTIAL_ANOMALY":
        # Root cannot have inline policies — this path only reached if enforcement_eligible=False
        # Return a documentation-only policy (never attached)
        return _deny_policy(
            sid="RootCredentialAnomalyAlert",
            actions=["*"],
            resources=["*"],
            conditions=None,
        )

    else:  # UNCERTAIN or unknown
        return _deny_policy(
            sid="CloudGuardUncertainAnomaly",
            actions=["*"],
            resources=["*"],
            conditions=None,
        )


def _deny_policy(
    sid: str,
    actions: list[str],
    resources: list[str],
    conditions: dict | None,
) -> dict:
    """Build a minimal valid IAM policy document with a single Deny statement."""
    statement: dict[str, Any] = {
        "Sid":      sid,
        "Effect":   "Deny",
        "Action":   actions,
        "Resource": resources,
    }
    if conditions:
        statement["Condition"] = conditions

    return {
        "Version":   "2012-10-17",
        "Statement": [statement],
    }


def _is_protected(arn: str, protected: frozenset[str]) -> bool:
    """Check if the given ARN matches any protected principal pattern."""
    if not arn:
        return False
    for pattern in protected:
        if pattern and (pattern in arn or arn.endswith(pattern)):
            return True
    return False

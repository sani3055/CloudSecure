"""
utils.py
========
Shared utilities for the CloudSecure Streamlit dashboard.
"""
import uuid
import random
from datetime import datetime, timedelta

import boto3
import pandas as pd
import streamlit as st

@st.cache_resource
def get_table():
    dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
    return dynamodb.Table("CloudGuard-ThreatEvents")

def generate_demo_data() -> pd.DataFrame:
    """Generate realistic SOC simulation data to populate the dashboard when live data is sparse."""
    from datetime import timezone
    now = datetime.now(timezone.utc)
    demo_events = []
    
    scenarios = [
        {"eventName": "PutUserPolicy", "mitre": "T1098 (Account Manipulation)", "rationale": "Anomalous inline IAM policy attached at unusual hour.", "sev": "Critical", "cat": "PRIVILEGE_ESCALATION", "score": 92, "is_anom": True},
        {"eventName": "DeleteTrail", "mitre": "T1562.008 (Disable CloudTrail)", "rationale": "CloudTrail logging disabled by non-admin role.", "sev": "Critical", "cat": "DEFENSE_EVASION", "score": 98, "is_anom": True},
        {"eventName": "AssumeRole", "mitre": "T1078 (Valid Accounts)", "rationale": "Role assumption from unusual geographic location (RU).", "sev": "High", "cat": "CREDENTIAL_ANOMALY", "score": 75, "is_anom": True},
        {"eventName": "ConsoleLogin", "mitre": "T1078 (Valid Accounts)", "rationale": "Login without MFA from new IP.", "sev": "Medium", "cat": "CREDENTIAL_ANOMALY", "score": 45, "is_anom": False},
        {"eventName": "DescribeInstances", "mitre": "N/A", "rationale": "Routine automated discovery.", "sev": "Low", "cat": "Unknown", "score": 12, "is_anom": False},
        {"eventName": "ListBuckets", "mitre": "N/A", "rationale": "Standard developer access.", "sev": "Low", "cat": "Unknown", "score": 8, "is_anom": False},
        {"eventName": "CreateAccessKey", "mitre": "T1098 (Account Manipulation)", "rationale": "Root user created access key.", "sev": "High", "cat": "CREDENTIAL_ANOMALY", "score": 85, "is_anom": True},
        {"eventName": "AuthorizeSecurityGroupIngress", "mitre": "T1562.007 (Disable Security Tools)", "rationale": "0.0.0.0/0 opened to port 22.", "sev": "High", "cat": "DEFENSE_EVASION", "score": 88, "is_anom": True},
        {"eventName": "PutBucketPublicAccessBlock", "mitre": "T1562 (Impair Defenses)", "rationale": "S3 block public access disabled.", "sev": "Critical", "cat": "DEFENSE_EVASION", "score": 95, "is_anom": True},
        {"eventName": "GetCallerIdentity", "mitre": "T1087 (Account Discovery)", "rationale": "Reconnaissance activity pattern detected.", "sev": "Medium", "cat": "CREDENTIAL_ANOMALY", "score": 55, "is_anom": True},
    ]
    
    regions = ["us-east-1", "eu-west-1", "ap-south-1", "ap-southeast-2", "eu-central-1"]
    users = ["IAMUser (dev-john)", "AssumedRole (jenkins-ci)", "Root", "IAMUser (audit-service)"]
    ips = ["192.168.1.5", "203.0.113.42", "198.51.100.7", "52.95.245.1"]
    
    # Generate exactly 10 demo events over the last 7 days (one for each scenario)
    for scenario in scenarios:
        offset = timedelta(hours=random.randint(0, 168), minutes=random.randint(0, 60))
        event_time = now - offset
        
        status = "NOT_REQUIRED"
        if scenario['is_anom']:
            status = random.choice(["PENDING_APPROVAL", "APPROVED", "SIMULATED", "BLOCKED"])
            
        demo_events.append({
            "eventId": f"DEMO-{uuid.uuid4().hex[:8]}",
            "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventName": scenario["eventName"],
            "awsRegion": random.choice(regions),
            "userIdentitytype": random.choice(users),
            "sourceIP": random.choice(ips),
            "riskScore": scenario["score"] + random.randint(-5, 5),
            "severity": scenario["sev"],
            "isAnomaly": scenario["is_anom"],
            "threat_category": scenario["cat"],
            "threat_rationale": scenario["rationale"],
            "mitre_technique": scenario["mitre"].split(" ")[0],
            "mitre_name": " ".join(scenario["mitre"].split(" ")[1:]).strip("()"),
            "confidence_level": "High" if scenario['score'] > 80 else "Medium",
            "remediation_status": status,
            "policy_json": '{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}' if scenario['is_anom'] else "",
            "policy_target_arn": f"arn:aws:iam::123456789012:user/demo-{random.randint(1,99)}",
            "validation_status": "CLEAN" if scenario['is_anom'] else "N/A",
            "is_demo": True
        })
        
    return pd.DataFrame(demo_events)

@st.cache_data(ttl=10)
def load_data(include_demo: bool = True) -> pd.DataFrame:
    """Load ThreatEvents. Generates SIMULATION data to ensure the UI is populated."""
    try:
        table = get_table()
        response = table.scan()
        items = response.get("Items", [])
    except Exception:
        items = []

    df_live = pd.DataFrame(items)
    if not df_live.empty:
        df_live['is_demo'] = False
        df = df_live
    else:
        df = pd.DataFrame()
        if include_demo:
            df = generate_demo_data()

    if df.empty:
        return df
    
    # Text Defaults
    str_defaults = {
        "eventId":           "Unknown",
        "eventName":         "Unknown",
        "awsRegion":         "Unknown",
        "severity":          "Unknown",
        "threat_label":      "Unknown",
        "mitre_technique":   "N/A",
        "mitre_name":        "N/A",
        "confidence_level":  "Unknown",
        "policy_name":       "N/A",
        "validation_status": "N/A",
        "remediation_status":"NOT_REQUIRED",
        "threat_rationale":  "",
        "policy_json":       "",
        "validation_findings": "",
        "policy_target_arn": "N/A",
        "threat_category":   "Unknown",
        "userIdentitytype":  "Unknown",
        "sourceIP":          "Unknown",
    }
    for col, default in str_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default).astype(str)
        else:
            df[col] = default
            
    if "riskScore" in df.columns:
        df["riskScore"] = pd.to_numeric(df["riskScore"], errors="coerce").fillna(0).astype(int)
    else:
        df["riskScore"] = 0
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", errors="coerce")

    # Normalize booleans
    for col in ("enforcement_eligible", "isAnomaly", "isRoot", "is_demo"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().isin(["true", "1"])
        else:
            df[col] = False

    return df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)

def update_remediation_status(event_id: str, new_status: str) -> bool:
    """Update status, execute remediation if APPROVED, and flush cache."""
    if event_id.startswith("DEMO-"):
        # Simulated UI update for demo events
        return True
        
    try:
        table = get_table()
        table.update_item(
            Key={"eventId": event_id},
            UpdateExpression="SET remediation_status = :s",
            ExpressionAttributeValues={":s": new_status},
        )
        if new_status == "APPROVED":
            import pipeline_runner
            pipeline_runner.execute_approved_remediation(event_id)

        load_data.clear()
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# CSS Injection
# ---------------------------------------------------------------------------
def inject_css() -> None:
    from pathlib import Path
    css_file = Path(__file__).parent / "assets" / "style.css"
    if css_file.exists():
        with open(css_file, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

def render_metric_card(title: str, value: str, accent: str = "info") -> str:
    """accent: critical, high, success, warning, info, purple"""
    return f"""
    <div class="cg-metric-card {accent}">
        <div class="cg-metric-title">{title}</div>
        <div class="cg-metric-value">{value}</div>
    </div>
    """

def render_badge(text: str, severity: str = "info") -> str:
    """severity: critical, high, medium, low, info, demo, success, warning, purple"""
    return f'<span class="cg-badge cg-badge-{severity.lower()}">{text}</span>'

def render_risk_gauge(score: int) -> str:
    if score >= 75:
        color = "var(--sev-critical)"
    elif score >= 50:
        color = "var(--sev-high)"
    elif score >= 25:
        color = "var(--sev-medium)"
    else:
        color = "var(--sev-low)"
        
    return f"""
    <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <div style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Assessed Risk Score</div>
        <div style="font-size: 2.5rem; font-weight: 700; line-height: 1; color: {color};">{score}</div>
        <div style="width: 100%; background-color: var(--border); height: 4px; border-radius: 2px; margin-top: 12px; overflow: hidden;">
            <div style="height: 100%; width: {score}%; background-color: {color};"></div>
        </div>
    </div>
    """

def render_investigation_row(key: str, val: str) -> str:
    return f"""
    <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border);">
        <div style="color: var(--text-muted); font-size: 12px; font-weight: 500;">{key}</div>
        <div style="color: var(--text-primary); font-size: 13px; font-weight: 600; text-align: right; max-width: 65%; word-wrap: break-word;">{val}</div>
    </div>
    """

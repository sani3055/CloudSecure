import streamlit as st
import pandas as pd
import json
import plotly.express as px
from utils import inject_css, load_data, render_badge, render_risk_gauge, render_investigation_row, update_remediation_status
import random

inject_css()

st.markdown("# Event Investigation")
st.markdown('<div class="cg-section-header">ML Anomaly Analysis & Response</div>', unsafe_allow_html=True)

df = load_data()
if df.empty:
    st.info("No cloud events to display.")
    st.stop()

# ── Filters ──
with st.expander("🔍 Filter Events", expanded=False):
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        sev_filter = st.multiselect("Severity", options=df['severity'].unique())
    with f2:
        anom_filter = st.selectbox("Type", options=["All", "Anomaly Only", "Normal Only"])
    with f3:
        status_filter = st.multiselect("Remediation Status", options=df['remediation_status'].unique())
    with f4:
        data_filter = st.selectbox("Data Source", options=["All", "Live AWS", "Demo/Simulation"])

# Apply filters
filtered_df = df.copy()
if sev_filter:
    filtered_df = filtered_df[filtered_df['severity'].isin(sev_filter)]
if anom_filter == "Anomaly Only":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == True]
elif anom_filter == "Normal Only":
    filtered_df = filtered_df[filtered_df['isAnomaly'] == False]
if status_filter:
    filtered_df = filtered_df[filtered_df['remediation_status'].isin(status_filter)]
if data_filter == "Live AWS":
    filtered_df = filtered_df[filtered_df['is_demo'] == False]
elif data_filter == "Demo/Simulation":
    filtered_df = filtered_df[filtered_df['is_demo'] == True]

if filtered_df.empty:
    st.success("No events match the current filters.")
    st.stop()

# ── Event Table ──
st.markdown("**Select an Event to Investigate:**")

# Using a selectbox for reliable selection across all Streamlit versions
event_options = []
for _, row in filtered_df.iterrows():
    prefix = "[DEMO] " if row['is_demo'] else "[LIVE] "
    event_options.append(f"{prefix}{row['eventId']} - {row['eventName']} ({row['severity']})")

selected_label = st.selectbox("Event ID", event_options, label_visibility="collapsed")
selected_event_id = selected_label.split(" ")[1] if "[DEMO]" in selected_label or "[LIVE]" in selected_label else selected_label.split(" ")[0]

# Display table
view_df = filtered_df[['timestamp', 'eventId', 'is_demo', 'eventName', 'userIdentitytype', 'awsRegion', 'severity', 'riskScore', 'remediation_status']].copy()
view_df['timestamp'] = view_df['timestamp'].astype(str)
view_df['Data'] = view_df['is_demo'].apply(lambda x: "DEMO" if x else "LIVE")
view_df = view_df.drop(columns=['is_demo'])
st.dataframe(view_df, use_container_width=True, hide_index=True)

st.markdown("---")
st.markdown('<div class="cg-section-header">Event Investigation Panel</div>', unsafe_allow_html=True)

# ── Investigation Panel ──
incident = filtered_df[filtered_df['eventId'] == selected_event_id].iloc[0]

c1, c2 = st.columns([2, 1])

with c1:
    st.markdown('<div class="cg-metric-card" style="padding:16px;">', unsafe_allow_html=True)
    st.markdown(render_investigation_row("Event ID", incident['eventId']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Data Source", "<span style='color:var(--sev-purple)'>DEMO/SIMULATION</span>" if incident['is_demo'] else "<span style='color:var(--sev-success)'>LIVE AWS</span>"), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Timestamp", str(incident['timestamp'])), unsafe_allow_html=True)
    st.markdown(render_investigation_row("API Action", incident['eventName']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Principal Type", incident['userIdentitytype']), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Source IP", incident.get('sourceIP', 'N/A')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("AWS Region", incident['awsRegion']), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown('<div class="cg-metric-card" style="padding:16px;">', unsafe_allow_html=True)
    st.markdown("**ML Intelligence & Operational Context**")
    st.markdown(render_investigation_row("Anomaly Category", incident.get('threat_category', 'Unknown')), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Rule/Technique", f"{incident.get('mitre_name', 'N/A')} ({incident.get('mitre_technique', 'N/A')})"), unsafe_allow_html=True)
    st.markdown(render_investigation_row("Confidence Level", incident.get('confidence_level', 'Unknown')), unsafe_allow_html=True)
    st.markdown(f"<div style='margin-top:12px; font-size:13px; color:var(--text-muted);'><b>ML / SHAP Rationale:</b> {incident.get('threat_rationale', 'No rationale provided.')}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown(render_risk_gauge(int(incident['riskScore'])), unsafe_allow_html=True)
    st.markdown(f"**Severity:** {render_badge(incident['severity'], incident['severity'])}", unsafe_allow_html=True)
    st.markdown(f"**Anomaly Status:** {render_badge('ANOMALY' if incident['isAnomaly'] else 'NORMAL', 'critical' if incident['isAnomaly'] else 'info')}", unsafe_allow_html=True)
    
    status = incident['remediation_status']
    status_badge_color = "info"
    if status == "PENDING_APPROVAL": status_badge_color = "warning"
    elif status == "APPROVED" or status == "ENFORCED": status_badge_color = "success"
    elif status == "BLOCKED" or status == "ROLLED_BACK": status_badge_color = "critical"
    
    st.markdown(f"**Remediation State:** {render_badge(status, status_badge_color)}", unsafe_allow_html=True)

# ── SHAP Visualization ──
st.markdown("### SHAP Feature Contributions")
st.markdown(
    "SHAP (SHapley Additive exPlanations) values show **exactly why** this event "
    "scored as it did. Negative values push toward Anomaly; positive values push toward Normal."
)

# ── Try to use real SHAP values from DynamoDB ─────────────────────────────────
shap_data = []
shap_source = "synthetic"

raw_shap = incident.get("xai_all_shap", None)
if raw_shap and isinstance(raw_shap, dict) and len(raw_shap) > 0:
    # Real SHAP from pipeline — keys are feature names, values are floats
    shap_data = [{"Feature": k, "Contribution": float(v)} for k, v in raw_shap.items()]
    shap_source = "real"
elif raw_shap and isinstance(raw_shap, str):
    # Stored as JSON string fallback
    try:
        parsed = json.loads(raw_shap)
        shap_data = [{"Feature": k, "Contribution": float(v)} for k, v in parsed.items()]
        shap_source = "real"
    except (json.JSONDecodeError, ValueError):
        pass

# Fallback: generate consistent synthetic SHAP (for demo events or missing data)
if not shap_data:
    random.seed(incident["eventId"])
    is_anom = incident["isAnomaly"]
    if is_anom:
        shap_data = [
            {"Feature": "eventName",        "Contribution": random.uniform(-0.40, -0.10)},
            {"Feature": "hour",             "Contribution": random.uniform(-0.25, -0.05)},
            {"Feature": "userIdentitytype", "Contribution": random.uniform(-0.15, -0.01)},
            {"Feature": "awsRegion",        "Contribution": random.uniform(-0.10,  0.05)},
            {"Feature": "isRoot",           "Contribution": random.uniform(-0.20,  0.00)},
        ]
    else:
        shap_data = [
            {"Feature": "eventName",        "Contribution": random.uniform( 0.05,  0.30)},
            {"Feature": "hour",             "Contribution": random.uniform( 0.02,  0.15)},
            {"Feature": "userIdentitytype", "Contribution": random.uniform( 0.01,  0.10)},
            {"Feature": "awsRegion",        "Contribution": random.uniform( 0.00,  0.08)},
            {"Feature": "isRoot",           "Contribution": random.uniform( 0.00,  0.05)},
        ]

shap_df = pd.DataFrame(shap_data)
# SHAP polarity: negative = pushes toward anomaly (shown in red), positive = pushes toward normal (blue)
shap_df["Direction"] = shap_df["Contribution"].apply(
    lambda x: "Pushes toward Anomaly" if x < 0 else "Pushes toward Normal"
)
shap_df = shap_df.sort_values("Contribution")

# Badge: real vs synthetic data source
source_badge = (
    "<span style='background:#1a6e36;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>REAL SHAP (from ML Pipeline)</span>"
    if shap_source == "real"
    else "<span style='background:#5a3e7a;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>SYNTHETIC (Demo fallback)</span>"
)
st.markdown(f"Data source: {source_badge}", unsafe_allow_html=True)

# Attribution confidence (real events only)
conf = incident.get("xai_attribution_confidence", None)
if conf and shap_source == "real":
    try:
        conf_val = float(conf)
        st.markdown(f"**Attribution Confidence:** `{conf_val:.2%}`")
    except (TypeError, ValueError):
        pass

fig_shap = px.bar(
    shap_df,
    y="Feature",
    x="Contribution",
    color="Direction",
    orientation="h",
    color_discrete_map={
        "Pushes toward Anomaly": "#e05252",
        "Pushes toward Normal":  "#4f86c6",
    },
    title=f"SHAP Feature Attribution — Event {incident['eventId']}",
)
fig_shap.update_layout(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(t=40, b=20, l=20, r=20),
    height=300,
    yaxis={"categoryorder": "total ascending"},
    legend_title_text="Direction",
)
fig_shap.add_vline(x=0, line_width=1, line_dash="dash", line_color="rgba(255,255,255,0.3)")
st.plotly_chart(fig_shap, use_container_width=True)

st.markdown("---")
st.markdown('<div class="cg-section-header">Cloud Operational Response</div>', unsafe_allow_html=True)

# Policy details
if status != "NOT_REQUIRED":
    with st.expander("View Proposed IAM Policy Details"):
        st.write(f"**Target ARN:** `{incident.get('policy_target_arn', 'N/A')}`")
        st.write(f"**Validation:** {incident.get('validation_status', 'N/A')}")
        try:
            pol_json = json.loads(incident.get("policy_json", "{}"))
            st.code(json.dumps(pol_json, indent=2), language="json")
        except:
            st.code(incident.get("policy_json", ""), language="json")

# Action Buttons
st.markdown("### Operational Actions")

if incident['is_demo']:
    st.markdown('<div class="cg-callout cg-callout-info">ℹ️ <b>DEMO EVENT</b>: Remediation actions will update the UI but will not execute on live AWS resources.</div>', unsafe_allow_html=True)

if status == "PENDING_APPROVAL":
    bc1, bc2 = st.columns(2)
    with bc1:
        if st.button("✅ APPROVE REMEDIATION", type="primary", use_container_width=True):
            with st.spinner("Executing IAM enforcement on AWS..." if not incident['is_demo'] else "Simulating IAM enforcement..."):
                success = update_remediation_status(incident['eventId'], "APPROVED")
                if success:
                    st.success("Remediation Approved and executed successfully!")
                    st.rerun()
                else:
                    st.error("Failed to execute remediation. Check backend logs.")
    with bc2:
        if st.button("❌ REJECT (FALSE POSITIVE)", use_container_width=True):
            success = update_remediation_status(incident['eventId'], "ROLLED_BACK")
            if success:
                st.success("Anomaly Rejected.")
                st.rerun()
elif status == "APPROVED" or status == "ENFORCED":
    st.success(f"This anomaly has already been {status}.")
elif status == "SIMULATED":
    st.info("This anomaly was SIMULATED. Enforcement is disabled for this record.")
elif status == "NOT_REQUIRED":
    st.info("No policy action was generated for this anomaly.")
else:
    st.warning(f"Current Status: {status}")

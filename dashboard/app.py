"""
Zero Trust AI Operations Center & Security Dashboard
Built with Streamlit
Visualizes NIST SP 800-207 Control Plane vs Data Plane,
real-time ML risk scoring, live network requests, and attack simulations.
"""

import streamlit as st
import pandas as pd
import requests
import json
import time

# Set page configuration
st.set_page_config(
    page_title="Zero Trust AI Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CONTROL_PLANE_URL = "http://127.0.0.1:8000"
PEP_URL = "http://127.0.0.1:8001"
BACKEND_URL = "http://127.0.0.1:8002"

# Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #e9ecef;
    }
    .badge-allow {
        background-color: #28a745;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-mfa {
        background-color: #ffc107;
        color: black;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-deny {
        background-color: #dc3545;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to check service status
def check_service(url):
    try:
        r = requests.get(url, timeout=1.0)
        return r.status_code == 200
    except:
        return False

# Top Header
st.title("🛡️ Zero Trust Architecture (ZTA) with AI-Powered UEBA")
st.caption("A NIST SP 800-207 Implementation featuring Machine Learning Dynamic Risk Scoring & Per-Session Verification")

# Service Health Bar
col_h1, col_h2, col_h3 = st.columns(3)
pe_ok = check_service(CONTROL_PLANE_URL)
pep_ok = check_service(PEP_URL)
vault_ok = check_service(BACKEND_URL)

col_h1.metric("Control Plane (PE / PA : 8000)", "ONLINE" if pe_ok else "OFFLINE")
col_h2.metric("Data Plane (PEP Gateway : 8001)", "ONLINE" if pep_ok else "OFFLINE")
col_h3.metric("Protected Database (: 8002)", "ONLINE" if vault_ok else "OFFLINE")

if not (pe_ok and pep_ok and vault_ok):
    st.warning("⚠️ One or more background microservices are not running. Run `python run_services.py` in your terminal to start all services.")

# Sidebar: Architecture Overview & Policy Thresholds
st.sidebar.header("⚙️ NIST Zero Trust Control Panel")

st.sidebar.markdown("""
**Core NIST 800-207 Tenets:**
1. Continuous Verification per session
2. Never Trust, Always Verify
3. Micro-segmentation & Least Privilege
4. Context-Aware UEBA Risk Scoring
""")

st.sidebar.subheader("Dynamic Risk Policy Thresholds")
allow_threshold = st.sidebar.slider("Maximum Risk for ALLOW", min_value=10, max_value=50, value=35)
mfa_threshold = st.sidebar.slider("Maximum Risk for STEP-UP MFA", min_value=50, max_value=85, value=65)

if st.sidebar.button("Update Policy Thresholds"):
    try:
        r = requests.post(
            f"{CONTROL_PLANE_URL}/update-thresholds",
            json={"allow_max_risk": allow_threshold, "mfa_max_risk": mfa_threshold},
            timeout=2.0
        )
        if r.status_code == 200:
            st.sidebar.success("Thresholds updated dynamically on Control Plane!")
    except Exception as e:
        st.sidebar.error(f"Failed to update thresholds: {e}")

# Main Tabs
tab_sandbox, tab_analytics, tab_architecture = st.tabs(["🧪 Interactive Attack Sandbox", "📊 Live Telemetry & Audit Logs", "📐 NIST 800-207 Architecture"])

# -------------------------------------------------------------
# TAB 1: INTERACTIVE ATTACK SANDBOX
# -------------------------------------------------------------
with tab_sandbox:
    st.subheader("Test Real-Time Traffic & Attack Scenarios")
    st.write("Trigger simulated personas or build a custom request to see the Policy Engine evaluate risk in real-time:")

    scenario_cols = st.columns(4)
    trigger_scenario = None

    if scenario_cols[0].button("🟢 1. Alice (Normal Employee)", use_container_width=True):
        trigger_scenario = {
            "user_id": "alice_finance", "source_ip": "192.168.1.105", "access_time_hour": 10.5,
            "day_of_week": 2, "ip_reputation_score": 0.02, "geo_distance_km": 8.0,
            "device_posture_score": 0.95, "requested_data_mb": 15.0, "request_rate_per_min": 4, "failed_logins_recent": 0
        }
    if scenario_cols[1].button("🟡 2. Bob (Off-Hours Remote)", use_container_width=True):
        trigger_scenario = {
            "user_id": "bob_sales", "source_ip": "172.16.50.22", "access_time_hour": 20.5,
            "day_of_week": 3, "ip_reputation_score": 0.15, "geo_distance_km": 85.0,
            "device_posture_score": 0.70, "requested_data_mb": 45.0, "request_rate_per_min": 8, "failed_logins_recent": 1
        }
    if scenario_cols[2].button("🔴 3. Eve (Foreign Credential Hacker)", use_container_width=True):
        trigger_scenario = {
            "user_id": "eve_hacker", "source_ip": "185.220.101.5", "access_time_hour": 3.4,
            "day_of_week": 5, "ip_reputation_score": 0.88, "geo_distance_km": 9400.0,
            "device_posture_score": 0.15, "requested_data_mb": 6200.0, "request_rate_per_min": 85, "failed_logins_recent": 8
        }
    if scenario_cols[3].button("🔴 4. Charlie (Insider Exfiltration)", use_container_width=True):
        trigger_scenario = {
            "user_id": "charlie_insider", "source_ip": "192.168.1.180", "access_time_hour": 14.0,
            "day_of_week": 1, "ip_reputation_score": 0.05, "geo_distance_km": 5.0,
            "device_posture_score": 0.90, "requested_data_mb": 8500.0, "request_rate_per_min": 110, "failed_logins_recent": 0
        }

    st.markdown("---")
    st.markdown("#### Custom Telemetry Builder")
    with st.expander("Configure Custom Network Request Parameters", expanded=(trigger_scenario is None)):
        c1, c2, c3 = st.columns(3)
        cust_user = c1.text_input("User ID", value=trigger_scenario["user_id"] if trigger_scenario else "user_delta")
        cust_ip = c2.text_input("Source IP", value=trigger_scenario["source_ip"] if trigger_scenario else "192.168.1.55")
        cust_hour = c3.slider("Access Hour (0.0 - 23.9)", 0.0, 23.9, value=float(trigger_scenario["access_time_hour"]) if trigger_scenario else 14.0, step=0.5)

        c4, c5, c6 = st.columns(3)
        cust_geo = c4.number_input("Geo Distance (km from baseline)", min_value=0.0, max_value=20000.0, value=float(trigger_scenario["geo_distance_km"]) if trigger_scenario else 10.0)
        cust_posture = c5.slider("Device Posture (0.0 Jailbreak - 1.0 Healthy)", 0.0, 1.0, value=float(trigger_scenario["device_posture_score"]) if trigger_scenario else 0.95, step=0.05)
        cust_ip_rep = c6.slider("IP Malicious Reputation (0.0 Clean - 1.0 TOR)", 0.0, 1.0, value=float(trigger_scenario["ip_reputation_score"]) if trigger_scenario else 0.05, step=0.05)

        c7, c8, c9 = st.columns(3)
        cust_data = c7.number_input("Requested Data Payload (MB)", min_value=1.0, max_value=15000.0, value=float(trigger_scenario["requested_data_mb"]) if trigger_scenario else 25.0)
        cust_rate = c8.number_input("Request Rate (req/min)", min_value=1, max_value=500, value=int(trigger_scenario["request_rate_per_min"]) if trigger_scenario else 5)
        cust_failed = c9.number_input("Recent Failed Logins", min_value=0, max_value=50, value=int(trigger_scenario["failed_logins_recent"]) if trigger_scenario else 0)

        custom_btn = st.button("🚀 Evaluate & Intercept Network Request")

    # Initialize session state for holding evaluations and MFA verification results
    if "active_eval_data" not in st.session_state:
        st.session_state["active_eval_data"] = None
    if "active_status_code" not in st.session_state:
        st.session_state["active_status_code"] = None
    if "mfa_records_data" not in st.session_state:
        st.session_state["mfa_records_data"] = None

    # Run execution if preset clicked or custom button clicked
    active_payload = trigger_scenario if trigger_scenario else {
        "user_id": cust_user, "source_ip": cust_ip, "access_time_hour": cust_hour,
        "day_of_week": 2, "ip_reputation_score": cust_ip_rep, "geo_distance_km": cust_geo,
        "device_posture_score": cust_posture, "requested_data_mb": cust_data,
        "request_rate_per_min": cust_rate, "failed_logins_recent": cust_failed
    }

    if trigger_scenario or custom_btn:
        with st.spinner("PEP Intercepting connection and consulting Control Plane..."):
            try:
                res = requests.post(f"{PEP_URL}/gateway/request-access", json=active_payload, timeout=5)
                st.session_state["active_status_code"] = res.status_code
                st.session_state["active_eval_data"] = res.json()
                st.session_state["mfa_records_data"] = None  # Reset any previous MFA data
            except Exception as e:
                st.error(f"Communication error with PEP Gateway: {e}")

    # Render results if an evaluation exists in session state
    if st.session_state.get("active_eval_data"):
        st.subheader("Inspection & Policy Engine Decision")
        resp_data = st.session_state["active_eval_data"]
        status_code = st.session_state["active_status_code"]

        if status_code == 200:
            decision = resp_data.get("decision")
            risk_score = resp_data.get("risk_score", 0)

            res_col1, res_col2 = st.columns([1, 2])
            with res_col1:
                st.metric("Calculated Risk Score", f"{risk_score} / 100")
                if decision == "ALLOW":
                    st.success("✅ DECISION: ALLOW (Implicit Trust Denied, Explicit Trust Granted)")
                elif decision == "STEP_UP_MFA":
                    st.warning("⚠️ DECISION: STEP-UP MFA (Context Uncertainty Detected)")

            with res_col2:
                st.write("**Evaluation Details:**")
                st.write(f"- **Risk Level:** `{resp_data.get('risk_level')}`")
                if decision == "ALLOW":
                    st.write(f"- **Session Token:** `{resp_data.get('session_token')[:25]}...` (Expires in {resp_data.get('token_validity_seconds')}s)")
                    # Automatically test data retrieval
                    fetch_res = requests.get(
                        f"{PEP_URL}/gateway/resource/financial-records",
                        headers={"Authorization": f"Bearer {resp_data.get('session_token')}"},
                        timeout=3
                    )
                    if fetch_res.status_code == 200:
                        st.success("🎉 Policy Enforcement Point forwarded request to Protected Database. Data retrieved:")
                        st.json(fetch_res.json()["data"][:3])
                elif decision == "STEP_UP_MFA":
                    st.info(f"Challenge ID: `{resp_data.get('challenge_id')}`. Enter OTP code below:")
                    otp_col1, otp_col2 = st.columns([2, 1])
                    otp_val = otp_col1.text_input("Enter MFA Code (Demo code: 123456)", value="123456")
                    if otp_col2.button("Verify MFA Challenge"):
                        with st.spinner("Verifying OTP and requesting Protected Database records..."):
                            mfa_verify = requests.post(
                                f"{PEP_URL}/gateway/solve-mfa",
                                json={"challenge_id": resp_data.get("challenge_id"), "mfa_code": otp_val}
                            )
                            if mfa_verify.status_code == 200:
                                mfa_token = mfa_verify.json().get("session_token")
                                # Retrieve data using the newly minted MFA session token!
                                fetch_mfa = requests.get(
                                    f"{PEP_URL}/gateway/resource/financial-records",
                                    headers={"Authorization": f"Bearer {mfa_token}"},
                                    timeout=3
                                )
                                if fetch_mfa.status_code == 200:
                                    st.session_state["mfa_records_data"] = fetch_mfa.json()["data"]
                                else:
                                    st.error("Failed to fetch database records with verified token.")
                            else:
                                st.error("MFA Verification Failed! Invalid OTP code.")

                    # If data was fetched post-MFA, display it cleanly on screen!
                    if st.session_state.get("mfa_records_data"):
                        st.success("🎉 MFA Passed & Verified! Policy Enforcement Point unlocked access to Protected Database:")
                        st.json(st.session_state["mfa_records_data"][:3])

        elif status_code == 403:
            err_info = resp_data.get("detail", {})
            risk_score = err_info.get("risk_score", 0)
            res_col1, res_col2 = st.columns([1, 2])
            with res_col1:
                st.metric("Calculated Risk Score", f"{risk_score} / 100")
                st.error("🚫 DECISION: DENIED & DROPPED")
            with res_col2:
                st.write("**Zero Trust Violation Detected:**")
                st.write(f"- **Risk Level:** `{err_info.get('risk_level')}`")
                st.write("**Identified Anomaly Indicators:**")
                for factor in err_info.get("risk_factors", []):
                    st.markdown(f"- 🚩 {factor}")

# -------------------------------------------------------------
# TAB 2: LIVE TELEMETRY & AUDIT LOGS
# -------------------------------------------------------------
with tab_analytics:
    st.subheader("Control Plane Audit Trail & Metrics")

    try:
        metrics_resp = requests.get(f"{CONTROL_PLANE_URL}/metrics", timeout=2)
        metrics = metrics_resp.json() if metrics_resp.status_code == 200 else {}
    except:
        metrics = {}

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Interceptions", metrics.get("total_requests", 0))
    m2.metric("Sessions Allowed", metrics.get("allowed", 0))
    m3.metric("MFA Step-Up Challenges", metrics.get("mfa_challenged", 0))
    m4.metric("Threats Blocked", metrics.get("denied", 0))

    st.markdown("#### Real-Time Security Audit Log")
    try:
        logs_resp = requests.get(f"{CONTROL_PLANE_URL}/audit-logs?limit=50", timeout=2)
        if logs_resp.status_code == 200 and logs_resp.json():
            logs_df = pd.DataFrame(logs_resp.json())
            # Format display
            disp_df = logs_df[["id", "timestamp", "user_id", "source_ip", "risk_score", "decision", "action_description"]]
            st.dataframe(disp_df.sort_values(by="id", ascending=False), use_container_width=True)
        else:
            st.info("No audit entries yet. Trigger some requests in the Sandbox tab.")
    except Exception as e:
        st.warning(f"Could not load audit logs: {e}")

# -------------------------------------------------------------
# TAB 3: NIST SP 800-207 ARCHITECTURE
# -------------------------------------------------------------
with tab_architecture:
    st.subheader("NIST SP 800-207 Architecture Alignment")
    st.markdown("""
    ### 🏛️ Control Plane vs. Data Plane
    
    ```
    +-----------------------------------------------------------------------------------------+
    |                                      CONTROL PLANE                                      |
    |                                                                                         |
    |  +--------------------------------+               +----------------------------------+  |
    |  |       Policy Engine (PE)       |<------------->|     Policy Administrator (PA)    |  |
    |  |  * ML Isolation Forest Model   |               |  * Generates Signed JWT Tokens   |  |
    |  |  * Context Risk Scoring (0-100)|               |  * Manages MFA Step-Up Challenges|  |
    |  +--------------------------------+               +----------------------------------+  |
    |                                   ^                                |                    |
    +-----------------------------------|--------------------------------|--------------------+
                                        | (Telemetry Check)              | (Access Decision)  
    +-----------------------------------|--------------------------------|--------------------+
    |                                   v                                v                    |
    |                             +----------------------------------------+                  |
    |  [ User / Client Device ]-->|    Policy Enforcement Point (PEP)      |                  |
    |                             |    (Port 8001 - Reverse Proxy Gateway) |                  |
    |                             +----------------------------------------+                  |
    |                                                  |                                      |
    |                                                  | (Only with X-PEP-Authorization)      |
    |                                                  v                                      |
    |                             +----------------------------------------+                  |
    |                             |      Protected Enterprise Resource     |                  |
    |                             |      (Port 8002 - Financial Records)   |                  |
    |                             +----------------------------------------+                  |
    |                                                                                         |
    |                                       DATA PLANE                                        |
    +-----------------------------------------------------------------------------------------+
    ```
    
    #### Key Computer Networking Concepts Demonstrated:
    1. **Separation of Control and Data Planes**: The Policy Enforcement Point (Data Plane) handles raw packet forwarding and filtering, while the Policy Engine (Control Plane) dictates policy and access decisions.
    2. **OSI Layer 7 Identity-Aware Proxying**: Instead of relying on static IP/Port firewall rules (Layer 3/4), every request is inspected at the Application Layer (Layer 7) with cryptographically verifiable session tokens.
    3. **Micro-Segmentation**: The backend database (Port 8002) is strictly segregated and will reject direct LAN traffic that bypasses the PEP gateway.
    4. **Continuous Per-Session Verification**: Sessions expire in 60 seconds, forcing the client to re-evaluate context and risk, mitigating credential replay attacks.
    """)

# Zero Trust Architecture (ZTA) with AI-Powered Risk Scoring (UEBA)

> **Course:** Computer Networks / Network Security (3rd Year Capstone / Lab Project)  
> **Standard:** [NIST SP 800-207 (Zero Trust Architecture)](https://csrc.nist.gov/pubs/sp/800/207/final)  
> **Core Principle:** *"Never Trust, Always Verify — Assume the Network is Compromised."*

---

## 📌 Executive Summary & Academic Alignment

Traditional perimeter security relies on the **"Castle-and-Moat" model**: once an entity crosses the perimeter (via VPN, physical LAN, or Wi-Fi password), it is implicitly trusted and can freely traverse internal network resources. If an attacker breaches a single employee machine, they can move **laterally** to compromise confidential databases.

This project implements a fully functional **Zero Trust Network Architecture** adhering to **NIST SP 800-207**, augmented with **Machine Learning User and Entity Behavior Analytics (UEBA)**. Every incoming packet is intercepted at the **Data Plane (Policy Enforcement Point)** and dynamically authorized by the **Control Plane (Policy Engine)** using real-time contextual risk scoring before any connection is permitted.

---

## 🏛️ NIST SP 800-207 Component Mapping

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

| NIST Component | File in Project | Network Port | Role & Function |
| :--- | :--- | :--- | :--- |
| **Policy Engine (PE)** | `control_plane/policy_engine.py` | `8000` | The ultimate decision-maker. Evaluates context telemetry with ML model to decide `ALLOW`, `STEP_UP_MFA`, or `DENY`. |
| **Policy Administrator (PA)**| `control_plane/policy_engine.py` | `8000` | The session manager. Generates cryptographically signed, short-lived session tokens (JWT) and coordinates MFA challenges. |
| **Policy Enforcement Point (PEP)** | `data_plane/gateway_pep.py` | `8001` | The network gatekeeper. Intercepts incoming client connections, questions the Control Plane, and forwards/drops packets. |
| **Protected Resource** | `protected_service/secure_api.py` | `8002` | Confidential backend asset. Rejects direct LAN requests; only permits packets mediated and signed by PEP. |
| **SOC Dashboard** | `dashboard/app.py` | `8501` | Real-time Streamlit operations console for live attack visualization, audit logs, and dynamic threshold tuning. |

---

## 🌐 Computer Networks Concepts Demonstrated

1. **Separation of Control Plane vs Data Plane:**
   - *Control Plane (Port 8000):* Decides *whether* packets are permitted to flow based on identity, risk, and state.
   - *Data Plane (Ports 8001 & 8002):* Executes packet interception, proxying, and dropping.
2. **Layer 7 Identity-Aware Routing vs Layer 3/4 Packet Filtering:**
   - Traditional firewalls inspect IP addresses and TCP ports (Layers 3 & 4).
   - Zero Trust inspects Application Layer payload, cryptographic tokens, user identities, and device health (Layer 7).
3. **Micro-Segmentation & Network Isolation:**
   - The backend resource (Port 8002) refuses direct requests. Even if an attacker is on the exact same internal subnet, direct packet transmission returns `HTTP 403 Forbidden`.
4. **Per-Session Dynamic Authorization:**
   - Access is not permanent. Session tokens expire in 60 seconds. Continuous re-evaluation prevents token replay and credential harvesting.

---

## 🤖 AI / Machine Learning Risk Scoring Pipeline (UEBA)

The system captures 8 real-time behavioral telemetry attributes on every connection attempt:

1. `access_time_hour`: Time of request (normal: 08:00–19:00, abnormal: 02:00–05:00)
2. `day_of_week`: Weekday vs weekend patterns
3. `ip_reputation_score`: Clean residential/office IP vs flagged TOR/VPN/Proxy exit node
4. `geo_distance_km`: Physical deviation from user's historical baseline (impossible travel detection)
5. `device_posture_score`: Endpoint integrity (OS patch level, active EDR/antivirus, disk encryption)
6. `requested_data_mb`: Volume of data requested (detects bulk exfiltration / database scraping)
7. `request_rate_per_min`: Frequency of packet requests (detects automated bot scripts / brute force)
8. `failed_logins_recent`: Recent authentication failures (detects credential stuffing)

### ML Architecture
- **Isolation Forest (Unsupervised Anomaly Detection):** Identifies subtle deviations from normal baseline behavior without requiring pre-labeled attack data.
- **Explainability Engine:** Translates raw anomaly scores and heuristic penalties into a human-readable **Risk Score (0–100)** and flags specific risk indicators.

### Threshold Enforcement Policy
- **Risk Score < 35 (`LOW`):** `ALLOW` $\rightarrow$ Control plane issues signed JWT session token (valid 60s).
- **Risk Score 35–65 (`MEDIUM`):** `STEP_UP_MFA` $\rightarrow$ Uncertainty detected; client must provide 2nd factor verification code.
- **Risk Score > 65 (`HIGH`):** `DENY` $\rightarrow$ Connection immediately terminated at PEP; packet dropped; security alert raised.

---

## 🚀 Quickstart Guide (Running in VS Code)

### Prerequisites
- Python 3.11+
- Virtual environment is already configured in `.venv/`

### 1. Run Automated Unit & Integration Tests
To verify all components, run:
```powershell
.venv\Scripts\python.exe test_flow.py
```
*(All 6 tests verify risk scoring, token issuance, MFA step-up, and direct bypass rejection.)*

### 2. Launch All Zero Trust Microservices & Visual Dashboard
Start all services with one command:
```powershell
.venv\Scripts\python.exe run_services.py
```

This starts:
- 🌐 **Control Plane (PE/PA):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- 🌐 **Data Plane (PEP Gateway):** [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)
- 🌐 **Protected Database:** [http://127.0.0.1:8002/docs](http://127.0.0.1:8002/docs)
- 📊 **Visual SOC Dashboard:** [http://127.0.0.1:8501](http://127.0.0.1:8501)

### 3. Run Simulated Attack Scenarios (CLI)
Open a second terminal in VS Code and run:
```powershell
.venv\Scripts\python.exe simulation\client_traffic_sim.py
```

The script executes 5 live scenarios:
1. **Alice (Legitimate Employee):** 10:30 AM, corporate IP, healthy device $\rightarrow$ **ALLOW (Risk ~4)** $\rightarrow$ Retrieves confidential records.
2. **Bob (Telecommuting Worker):** 8:30 PM, remote IP $\rightarrow$ **STEP-UP MFA (Risk ~45)** $\rightarrow$ Solves OTP $\rightarrow$ Access granted.
3. **Eve (External Attacker with Stolen Password):** 3:20 AM, TOR exit node, 9,400 km away $\rightarrow$ **DENY (Risk ~85)** $\rightarrow$ PEP terminates connection!
4. **Charlie (Malicious Insider Exfiltration):** Corporate IP, but requesting 8,500 MB data dump $\rightarrow$ **DENY (Risk ~82)** $\rightarrow$ Exfiltration blocked!
5. **Direct Perimeter Bypass:** Attacker attempts direct connection to Port 8002 bypassing PEP $\rightarrow$ **Blocked by backend Zero Trust policy**.

---

## 🎓 Viva / Oral Exam Q&A Preparation

**Q1: How does Zero Trust differ from traditional network perimeter security?**  
> *Answer:* Traditional security relies on the "castle-and-moat" paradigm where anything inside the network perimeter is implicitly trusted. Zero Trust removes implicit trust and enforces continuous verification on every single request, regardless of whether it originates from inside or outside the local network.

**Q2: What are the three core logical components of NIST SP 800-207?**  
> *Answer:* 
> 1. **Policy Engine (PE):** Evaluates enterprise policy and telemetry to decide access (Allow/Deny).
> 2. **Policy Administrator (PA):** Issues and revokes session tokens and commands the enforcement point.
> 3. **Policy Enforcement Point (PEP):** Intercepts and terminates packet connections based on PA instructions.

**Q3: Why use an Isolation Forest rather than standard static firewall rules?**  
> *Answer:* Static firewall rules (e.g. iptables) only check static Layer 3/4 headers (IP and Port) and cannot detect stolen credentials used from an anomalous location or off-hours bulk data exfiltration. Isolation Forest performs multi-dimensional anomaly detection on behavioral telemetry (time, volume, device posture, frequency) to compute dynamic risk scores.

**Q4: How does your system stop lateral movement?**  
> *Answer:* Through micro-segmentation. The protected backend only accepts connections containing a cryptographic PEP assertion header. An attacker on the same local network subnet cannot access backend resources directly.

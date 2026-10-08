"""
Zero Trust Traffic Simulator & Attack Scenarios
Executes 5 live test scenarios against the Zero Trust architecture:
1. Alice (Legitimate Employee) -> ALLOW
2. Bob (Telecommuter with minor deviation) -> STEP-UP MFA -> ALLOW
3. Eve (Attacker with stolen credentials & TOR IP) -> DENY & DROP
4. Charlie (Insider Data Exfiltration Attempt) -> DENY & DROP
5. Direct Perimeter Bypass Attempt -> DENIED AT RESOURCE
"""

import requests
import json
import time

PEP_URL = "http://127.0.0.1:8001"
BACKEND_DIRECT_URL = "http://127.0.0.1:8002"

SCENARIOS = [
    {
        "name": "Scenario 1: Alice (Trusted Employee during business hours)",
        "user_id": "alice_finance",
        "source_ip": "192.168.1.105",
        "access_time_hour": 10.5,
        "day_of_week": 2,
        "ip_reputation_score": 0.02,
        "geo_distance_km": 8.0,
        "device_posture_score": 0.95,
        "requested_data_mb": 15.0,
        "request_rate_per_min": 4,
        "failed_logins_recent": 0,
        "expected": "ALLOW"
    },
    {
        "name": "Scenario 2: Bob (Remote Worker with Moderate Risk / Off-Hours)",
        "user_id": "bob_sales",
        "source_ip": "172.16.50.22",
        "access_time_hour": 20.5,
        "day_of_week": 3,
        "ip_reputation_score": 0.15,
        "geo_distance_km": 85.0,
        "device_posture_score": 0.70,
        "requested_data_mb": 45.0,
        "request_rate_per_min": 8,
        "failed_logins_recent": 1,
        "expected": "STEP_UP_MFA"
    },
    {
        "name": "Scenario 3: Eve (External Attacker with Stolen Password & Foreign IP)",
        "user_id": "eve_hacker",
        "source_ip": "185.220.101.5",
        "access_time_hour": 3.4,
        "day_of_week": 5,
        "ip_reputation_score": 0.88,
        "geo_distance_km": 9400.0,
        "device_posture_score": 0.15,
        "requested_data_mb": 6200.0,
        "request_rate_per_min": 85,
        "failed_logins_recent": 8,
        "expected": "DENY"
    },
    {
        "name": "Scenario 4: Charlie (Compromised Insider attempting Massive Data Dump)",
        "user_id": "charlie_insider",
        "source_ip": "192.168.1.180",
        "access_time_hour": 14.0,
        "day_of_week": 1,
        "ip_reputation_score": 0.05,
        "geo_distance_km": 5.0,
        "device_posture_score": 0.90,
        "requested_data_mb": 8500.0,
        "request_rate_per_min": 110,
        "failed_logins_recent": 0,
        "expected": "DENY"
    }
]

def run_simulation():
    print("=" * 75)
    print("      ZERO TRUST AI ARCHITECTURE: LIVE NETWORK TRAFFIC SIMULATION     ")
    print("=" * 75)

    for sc in SCENARIOS:
        print(f"\n[+] Executing: {sc['name']}")
        print(f"    User: {sc['user_id']} | Time: {int(sc['access_time_hour']):02d}:{int((sc['access_time_hour']%1)*60):02d} | IP: {sc['source_ip']}")
        print(f"    Data: {sc['requested_data_mb']} MB | Device Posture: {sc['device_posture_score']} | Geo: {sc['geo_distance_km']} km")

        # Step 1: Request access through PEP Gateway
        try:
            req_payload = {
                "user_id": sc["user_id"],
                "source_ip": sc["source_ip"],
                "access_time_hour": sc["access_time_hour"],
                "day_of_week": sc["day_of_week"],
                "ip_reputation_score": sc["ip_reputation_score"],
                "geo_distance_km": sc["geo_distance_km"],
                "device_posture_score": sc["device_posture_score"],
                "requested_data_mb": sc["requested_data_mb"],
                "request_rate_per_min": sc["request_rate_per_min"],
                "failed_logins_recent": sc["failed_logins_recent"]
            }
            res = requests.post(f"{PEP_URL}/gateway/request-access", json=req_payload, timeout=5)
            
            if res.status_code == 200:
                data = res.json()
                decision = data.get("decision")
                risk = data.get("risk_score")
                print(f"    --> PEP Result: HTTP 200 | Decision: {decision} (Risk Score: {risk}/100)")
                
                if decision == "ALLOW":
                    token = data.get("session_token")
                    print("    --> Cryptographic Session Token Granted!")
                    # Access confidential resource with token
                    fetch_res = requests.get(
                        f"{PEP_URL}/gateway/resource/financial-records",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5
                    )
                    if fetch_res.status_code == 200:
                        records = fetch_res.json()
                        print(f"    --> Successfully retrieved {records.get('records_count')} confidential records from backend vault.")
                    else:
                        print(f"    --> Backend fetch failed: {fetch_res.status_code}")

                elif decision == "STEP_UP_MFA":
                    challenge_id = data.get("challenge_id")
                    print(f"    --> Step-Up Required! MFA Challenge ID: {challenge_id}")
                    print("    --> Submitting simulated 2nd Factor TOTP (Code: 123456)...")
                    mfa_res = requests.post(
                        f"{PEP_URL}/gateway/solve-mfa",
                        json={"challenge_id": challenge_id, "mfa_code": "123456"},
                        timeout=5
                    )
                    if mfa_res.status_code == 200:
                        mfa_token = mfa_res.json().get("session_token")
                        print("    --> MFA Verified! Stepped-down to ALLOW. Session token acquired.")
                        fetch_res = requests.get(
                            f"{PEP_URL}/gateway/resource/financial-records",
                            headers={"Authorization": f"Bearer {mfa_token}"},
                            timeout=5
                        )
                        print(f"    --> Retrieved {fetch_res.json().get('records_count')} records post-MFA verification.")
                    else:
                        print("    --> MFA verification failed.")

            elif res.status_code == 403:
                err_detail = res.json().get("detail", {})
                risk = err_detail.get("risk_score")
                factors = err_detail.get("risk_factors", [])
                print(f"    --> PEP Result: HTTP 403 FORBIDDEN | Decision: DENY (Risk Score: {risk}/100)")
                print(f"    --> ZERO TRUST POLICY TRIGGERED: Connection terminated immediately!")
                print(f"    --> Flagged Risk Factors:")
                for f in factors:
                    print(f"        * {f}")
            else:
                print(f"    --> Unexpected status: {res.status_code} - {res.text}")

        except Exception as e:
            print(f"    --> Connection Error: {e}")

    # Step 5: Direct Perimeter Bypass Test
    print("\n" + "=" * 75)
    print("[+] Scenario 5: Direct Perimeter Bypass Attack (Simulating LAN Attacker)")
    print("    Attacker bypasses PEP (Port 8001) and connects directly to Protected Database (Port 8002)")
    try:
        bypass_res = requests.get(f"{BACKEND_DIRECT_URL}/api/v1/financial-records", timeout=5)
        print(f"    --> Target Response: HTTP {bypass_res.status_code}")
        print(f"    --> Payload: {bypass_res.text}")
    except Exception as e:
        print(f"    --> Bypass Attempt Blocked: {e}")

    print("\n" + "=" * 75)
    print("                     SIMULATION RUN COMPLETED                        ")
    print("=" * 75)

if __name__ == "__main__":
    run_simulation()

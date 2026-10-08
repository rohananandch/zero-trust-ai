"""
Zero Trust Risk Scorer & Explainability Engine
Loads the trained ML model and baseline statistics to compute real-time
Risk Scores (0-100) and NIST Policy Recommendations (ALLOW, STEP_UP_MFA, DENY).
"""

import os
import joblib
import numpy as np
import pandas as pd

class ZeroTrustRiskScorer:
    def __init__(self, model_path: str = None):
        if model_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "risk_model.joblib")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model artifact not found at {model_path}. Run train_model.py first.")
            
        artifact = joblib.load(model_path)
        self.iso_forest = artifact["isolation_forest"]
        self.rf = artifact["random_forest"]
        self.scaler = artifact["scaler"]
        self.features = artifact["features"]
        self.stats = artifact["baseline_stats"]

    def evaluate_request(self, telemetry: dict) -> dict:
        """
        Evaluates incoming client telemetry and computes:
        - risk_score (0 - 100)
        - risk_level ('LOW', 'MEDIUM', 'HIGH')
        - decision ('ALLOW', 'STEP_UP_MFA', 'DENY')
        - risk_factors: list of diagnostic explanations
        - anomaly_probability: ML probability score
        """
        # Extract features in correct order
        feature_values = [
            float(telemetry.get(f, 0.0)) for f in self.features
        ]
        
        sample_df = pd.DataFrame([feature_values], columns=self.features)
        sample_scaled = self.scaler.transform(sample_df)

        # 1. Isolation Forest score
        # decision_function yields higher values for inliers, negative for anomalies
        raw_iso = float(self.iso_forest.decision_function(sample_scaled)[0])
        # Scale to 0-1 anomaly score (approx: 0.15 is very normal, -0.2 is very abnormal)
        # Using sigmoid transformation
        anomaly_factor = float(1.0 / (1.0 + np.exp(raw_iso * 12.0)))

        # 2. Supervised RF probability
        rf_prob = float(self.rf.predict_proba(sample_df)[0][1])

        # 3. Contextual Rule & Heuristic Penalty Checks (NIST Explainability)
        risk_factors = []
        heuristic_points = 0.0

        hour = telemetry.get("access_time_hour", 12.0)
        if hour < 6.0 or hour > 21.0:
            heuristic_points += 20.0
            risk_factors.append(f"Off-hours access attempt at {int(hour):02d}:{int((hour%1)*60):02d}")

        geo_km = telemetry.get("geo_distance_km", 0.0)
        if geo_km > 300.0:
            heuristic_points += 25.0
            risk_factors.append(f"Significant geographic anomaly ({geo_km:,.1f} km from baseline)")
        elif geo_km > 75.0:
            heuristic_points += 10.0
            risk_factors.append(f"Moderate distance deviation ({geo_km:.1f} km)")

        posture = telemetry.get("device_posture_score", 1.0)
        if posture < 0.50:
            heuristic_points += 30.0
            risk_factors.append(f"Critical device posture failure: score {posture:.2f} (OS unpatched or missing EDR)")
        elif posture < 0.75:
            heuristic_points += 15.0
            risk_factors.append(f"Sub-optimal device hygiene: posture score {posture:.2f}")

        data_mb = telemetry.get("requested_data_mb", 10.0)
        if data_mb > 500.0:
            heuristic_points += 30.0
            risk_factors.append(f"Massive data payload request: {data_mb:,.1f} MB (Potential Exfiltration)")
        elif data_mb > 75.0:
            heuristic_points += 12.0
            risk_factors.append(f"Elevated data volume requested: {data_mb:.1f} MB")

        ip_rep = telemetry.get("ip_reputation_score", 0.0)
        if ip_rep > 0.50:
            heuristic_points += 35.0
            risk_factors.append(f"Suspicious IP reputation ({ip_rep:.2f}): TOR")
        elif ip_rep > 0.25:
            heuristic_points += 15.0
            risk_factors.append(f"Moderate IP reputation risk ({ip_rep:.2f})")

        failed_logins = telemetry.get("failed_logins_recent", 0)
        if failed_logins >= 4:
            heuristic_points += 30.0
            risk_factors.append(f"Multiple consecutive failed authentication attempts ({failed_logins})")
        elif failed_logins >= 2:
            heuristic_points += 12.0
            risk_factors.append(f"Recent failed login detected ({failed_logins})")

        req_rate = telemetry.get("request_rate_per_min", 5)
        if req_rate > 50:
            heuristic_points += 25.0
            risk_factors.append(f"High automated request frequency ({req_rate} req/min)")

        # 4. Synthesize Final Risk Score (0 - 100)
        # Weighted combination: 45% ML Anomaly Detection + 35% Heuristics + 20% Supervised Benchmark
        blended_score = (anomaly_factor * 45.0) + (min(heuristic_points, 100.0) * 0.35) + (rf_prob * 20.0)
        risk_score = int(np.clip(np.round(blended_score), 0, 100))

        # 5. Policy Decision based on Zero Trust Thresholds
        if risk_score < 35:
            risk_level = "LOW"
            decision = "ALLOW"
            action_description = "Implicit trust denied, explicit trust granted. Issued short-lived session token."
            if not risk_factors:
                risk_factors.append("Nominal baseline telemetry across all parameters")
        elif risk_score <= 65:
            risk_level = "MEDIUM"
            decision = "STEP_UP_MFA"
            action_description = "Context uncertainty detected. Multi-factor challenge mandated before access."
        else:
            risk_level = "HIGH"
            decision = "DENY"
            action_description = "Zero Trust violation. Packet dropped at Policy Enforcement Point (PEP)."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "action_description": action_description,
            "risk_factors": risk_factors,
            "ml_anomaly_prob": round(anomaly_factor, 3),
            "rf_prob": round(rf_prob, 3),
            "heuristic_points": round(heuristic_points, 1),
            "evaluated_telemetry": telemetry
        }

if __name__ == "__main__":
    scorer = ZeroTrustRiskScorer()
    
    # Test 1: Normal access
    print("\n--- Testing Alice (Normal Employee) ---")
    res1 = scorer.evaluate_request({
        "access_time_hour": 11.5,
        "day_of_week": 2,
        "ip_reputation_score": 0.02,
        "geo_distance_km": 12.0,
        "device_posture_score": 0.95,
        "requested_data_mb": 25.0,
        "request_rate_per_min": 6,
        "failed_logins_recent": 0
    })
    print(f"Risk Score: {res1['risk_score']} | Level: {res1['risk_level']} | Decision: {res1['decision']}")
    print("Factors:", res1["risk_factors"])

    # Test 2: Attacker access
    print("\n--- Testing Eve (Off-hours Exfiltration Attack) ---")
    res2 = scorer.evaluate_request({
        "access_time_hour": 3.25,
        "day_of_week": 4,
        "ip_reputation_score": 0.85,
        "geo_distance_km": 8500.0,
        "device_posture_score": 0.20,
        "requested_data_mb": 4500.0,
        "request_rate_per_min": 80,
        "failed_logins_recent": 6
    })
    print(f"Risk Score: {res2['risk_score']} | Level: {res2['risk_level']} | Decision: {res2['decision']}")
    print("Factors:", res2["risk_factors"])

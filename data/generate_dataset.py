"""
Synthetic Dataset Generator for Zero Trust UEBA (User and Entity Behavior Analytics)
Simulates baseline user behavioral telemetry:
- access_time_hour (0.0 - 23.99)
- day_of_week (0: Mon, ..., 6: Sun)
- ip_reputation_score (0.0 clean to 1.0 malicious)
- geo_distance_km (distance from typical baseline location)
- device_posture_score (0.0 unmanaged/compromised to 1.0 fully compliant)
- requested_data_mb (requested payload size)
- request_rate_per_min (frequency of requests)
- failed_logins_recent (count of recent failed attempts)
- is_anomaly (0: normal, 1: anomaly)
"""

import numpy as np
import pandas as pd
import os

def generate_user_behavior_dataset(num_samples: int = 3000, anomaly_ratio: float = 0.15, random_state: int = 42) -> pd.DataFrame:
    np.random.seed(random_state)
    num_anomalies = int(num_samples * anomaly_ratio)
    num_normal = num_samples - num_anomalies

    # -----------------------------
    # 1. NORMAL USERS (Employees during work hours, trusted devices)
    # -----------------------------
    # Work hours: centered around 13:00 (1 PM) with std 3.5, clipped to 8 - 19
    normal_hours = np.clip(np.random.normal(loc=13.0, scale=3.0, size=num_normal), 7.0, 20.0)
    
    # Normal days: mostly weekdays (0-4), rare weekends (5-6)
    normal_days = np.random.choice([0, 1, 2, 3, 4, 5, 6], size=num_normal, p=[0.20, 0.20, 0.20, 0.20, 0.15, 0.03, 0.02])
    
    # IP reputation: clean (close to 0.0)
    normal_ip_rep = np.clip(np.random.beta(a=1, b=30, size=num_normal), 0.0, 0.25)
    
    # Geo distance: local/metro radius (0 - 45 km)
    normal_geo = np.clip(np.random.exponential(scale=10.0, size=num_normal), 0.0, 60.0)
    
    # Device posture: high compliance (antivirus on, OS patched, disk encrypted)
    normal_posture = np.clip(np.random.beta(a=25, b=2, size=num_normal), 0.70, 1.0)
    
    # Requested data size: typical API usage 5MB - 50MB
    normal_data_mb = np.clip(np.random.gamma(shape=3.0, scale=8.0, size=num_normal), 1.0, 75.0)
    
    # Request rate: typical human navigation (2 - 12 requests/min)
    normal_rate = np.clip(np.random.poisson(lam=5.0, size=num_normal), 1, 15)
    
    # Failed logins: 0 or occasionally 1 typo
    normal_failed = np.random.choice([0, 1, 2], size=num_normal, p=[0.88, 0.10, 0.02])

    normal_df = pd.DataFrame({
        "access_time_hour": np.round(normal_hours, 2),
        "day_of_week": normal_days,
        "ip_reputation_score": np.round(normal_ip_rep, 3),
        "geo_distance_km": np.round(normal_geo, 1),
        "device_posture_score": np.round(normal_posture, 2),
        "requested_data_mb": np.round(normal_data_mb, 1),
        "request_rate_per_min": normal_rate,
        "failed_logins_recent": normal_failed,
        "is_anomaly": 0
    })

    # -----------------------------
    # 2. ANOMALIES / ATTACK TRAFFIC
    # -----------------------------
    # Attacks happen at odd hours (late night 00:00 - 05:00)
    anomaly_hours = np.random.choice(
        np.concatenate([np.random.uniform(0.0, 5.5, int(num_anomalies * 0.7)),
                        np.random.uniform(22.0, 23.9, int(num_anomalies * 0.3))])
    )
    anomaly_days = np.random.choice([0, 1, 2, 3, 4, 5, 6], size=num_anomalies)

    # Malicious or suspicious IP reputation (proxies, VPNs, TOR exit nodes)
    anomaly_ip_rep = np.clip(np.random.beta(a=8, b=2, size=num_anomalies), 0.4, 1.0)

    # Extreme geo distances (foreign countries, cross-continental logins: 1,500 - 12,000 km)
    anomaly_geo = np.random.uniform(1500.0, 12000.0, size=num_anomalies)

    # Device posture: poor (compromised, outdated, root/jailbreak, no EDR)
    anomaly_posture = np.clip(np.random.beta(a=2, b=10, size=num_anomalies), 0.05, 0.55)

    # Massive data exfiltration spikes (500MB - 10,000MB)
    anomaly_data_mb = np.random.uniform(300.0, 8000.0, size=num_anomalies)

    # Automated script / scraping / brute force rates (40 - 250 req/min)
    anomaly_rate = np.random.randint(35, 200, size=num_anomalies)

    # Failed login attempts (brute force spikes: 4 - 25)
    anomaly_failed = np.random.randint(3, 20, size=num_anomalies)

    anomaly_df = pd.DataFrame({
        "access_time_hour": np.round(anomaly_hours, 2),
        "day_of_week": anomaly_days,
        "ip_reputation_score": np.round(anomaly_ip_rep, 3),
        "geo_distance_km": np.round(anomaly_geo, 1),
        "device_posture_score": np.round(anomaly_posture, 2),
        "requested_data_mb": np.round(anomaly_data_mb, 1),
        "request_rate_per_min": anomaly_rate,
        "failed_logins_recent": anomaly_failed,
        "is_anomaly": 1
    })

    # Combine and shuffle
    dataset = pd.concat([normal_df, anomaly_df], ignore_index=True)
    dataset = dataset.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return dataset

if __name__ == "__main__":
    output_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(output_dir, "user_behavior.csv")
    df = generate_user_behavior_dataset(num_samples=3000, anomaly_ratio=0.15)
    df.to_csv(output_path, index=False)
    print(f"Generated synthetic Zero Trust dataset with {len(df)} samples ({df['is_anomaly'].sum()} anomalies).")
    print(f"Saved to: {output_path}")
    print("\nSample Preview:")
    print(df.head())

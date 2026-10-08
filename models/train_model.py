"""
Zero Trust Risk Model Training
Trains an Isolation Forest (Unsupervised Anomaly Detection)
plus a Random Forest Classifier for baseline evaluation and feature importance.
Saves the trained pipeline, scaler, and metadata to models/risk_model.joblib.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

FEATURE_COLUMNS = [
    "access_time_hour",
    "day_of_week",
    "ip_reputation_score",
    "geo_distance_km",
    "device_posture_score",
    "requested_data_mb",
    "request_rate_per_min",
    "failed_logins_recent"
]

def train_and_save_model():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(current_dir, "..", "data", "user_behavior.csv")
    model_output_path = os.path.join(current_dir, "risk_model.joblib")

    print(f"Loading training data from {data_path}...")
    df = pd.read_csv(data_path)

    X = df[FEATURE_COLUMNS]
    y = df["is_anomaly"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 1. Feature Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 2. Train Isolation Forest (UEBA Core - Unsupervised Anomaly Detection)
    # Contamination matches expected anomaly frequency ~15%
    print("Training Isolation Forest anomaly detector...")
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.15,
        max_samples="auto",
        random_state=42
    )
    # Isolation forest trains on normal data + representative baseline
    iso_forest.fit(X_train_scaled)

    # Invert decision function: lower decision score = more anomalous
    raw_scores = iso_forest.decision_function(X_test_scaled)
    # Anomaly predictions: -1 (anomaly) -> map to 1, 1 (normal) -> map to 0
    iso_preds = np.where(iso_forest.predict(X_test_scaled) == -1, 1, 0)

    # 3. Supervised Model (Random Forest) for feature importance & benchmarking
    print("Training Random Forest for benchmark metrics and feature importance...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]

    # Evaluation Output
    print("\n================ MODEL PERFORMANCE EVALUATION ================")
    print("\n--- Isolation Forest Anomaly Detection (Zero Trust UEBA) ---")
    print(classification_report(y_test, iso_preds, target_names=["Normal", "Anomaly"]))

    print("--- Supervised Benchmark (Random Forest) ---")
    print(classification_report(y_test, rf_preds, target_names=["Normal", "Anomaly"]))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, rf_probs):.4f}")

    print("\n--- Feature Importance in Access Risk ---")
    for feat, imp in sorted(zip(FEATURE_COLUMNS, rf.feature_importances_), key=lambda x: x[1], reverse=True):
        print(f"  {feat:<25}: {imp * 100:.2f}%")

    # Save artifacts bundle
    model_artifact = {
        "isolation_forest": iso_forest,
        "random_forest": rf,
        "scaler": scaler,
        "features": FEATURE_COLUMNS,
        "feature_importances": dict(zip(FEATURE_COLUMNS, rf.feature_importances_)),
        # Normal baseline thresholds for heuristic explainability
        "baseline_stats": {
            "mean_hour": float(df[df["is_anomaly"] == 0]["access_time_hour"].mean()),
            "std_hour": float(df[df["is_anomaly"] == 0]["access_time_hour"].std()),
            "max_normal_geo": float(df[df["is_anomaly"] == 0]["geo_distance_km"].quantile(0.99)),
            "max_normal_data": float(df[df["is_anomaly"] == 0]["requested_data_mb"].quantile(0.99)),
            "min_normal_posture": float(df[df["is_anomaly"] == 0]["device_posture_score"].quantile(0.01)),
            "max_normal_rate": float(df[df["is_anomaly"] == 0]["request_rate_per_min"].quantile(0.99))
        }
    }

    joblib.dump(model_artifact, model_output_path)
    print(f"\nModel pipeline successfully saved to: {model_output_path}")

if __name__ == "__main__":
    train_and_save_model()

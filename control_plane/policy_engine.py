"""
NIST SP 800-207 Control Plane: Policy Engine (PE) & Policy Administrator (PA)
Runs on http://127.0.0.1:8000

Responsibilities:
- Evaluates access requests using Context-Aware ML UEBA (RiskScorer).
- Issues short-lived, cryptographically signed JWT session tokens.
- Manages dynamic step-up authentication challenges.
- Maintains live audit logs and telemetry for dashboard observability.
"""

import sys
import os
import time
import jwt
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from models.risk_scorer import ZeroTrustRiskScorer

app = FastAPI(
    title="Zero Trust Control Plane (Policy Engine / Administrator)",
    description="NIST SP 800-207 Core Control Plane with AI/ML UEBA Risk Scoring",
    version="1.0.0"
)

# Initialize Risk Scorer
scorer = ZeroTrustRiskScorer()

JWT_SECRET = "zero-trust-quantum-secret-key-2026"
JWT_ALGORITHM = "HS256"
TOKEN_VALIDITY_SECONDS = 60

# In-memory storage for active sessions, challenges, audit logs, and dynamic thresholds
active_sessions: Dict[str, dict] = {}
pending_mfa_challenges: Dict[str, dict] = {}
audit_logs: List[dict] = []
policy_thresholds = {
    "allow_max_risk": 35,
    "mfa_max_risk": 65
}

class TelemetryPayload(BaseModel):
    user_id: str = Field(..., example="alice")
    source_ip: str = Field("192.168.1.50", example="192.168.1.50")
    access_time_hour: float = Field(..., example=14.5)
    day_of_week: int = Field(2, example=2)
    ip_reputation_score: float = Field(0.05, example=0.05)
    geo_distance_km: float = Field(15.0, example=15.0)
    device_posture_score: float = Field(0.95, example=0.95)
    requested_data_mb: float = Field(20.0, example=20.0)
    request_rate_per_min: int = Field(5, example=5)
    failed_logins_recent: int = Field(0, example=0)
    requested_resource: str = Field("/api/v1/financial-records", example="/api/v1/financial-records")

class VerifyTokenPayload(BaseModel):
    token: str

class StepUpPayload(BaseModel):
    challenge_id: str
    mfa_code: str

class ThresholdUpdatePayload(BaseModel):
    allow_max_risk: int
    mfa_max_risk: int

@app.get("/")
def control_plane_root():
    return {
        "component": "NIST SP 800-207 Policy Engine & Policy Administrator (Control Plane)",
        "status": "ONLINE",
        "active_thresholds": policy_thresholds,
        "active_sessions_count": len(active_sessions),
        "total_audits_recorded": len(audit_logs)
    }

@app.post("/evaluate-policy")
def evaluate_policy(payload: TelemetryPayload):
    """
    Core Policy Engine decision point:
    1. Evaluates incoming context telemetry via ML Risk Scorer
    2. Compares risk against dynamic policy thresholds
    3. Returns ALLOW, STEP_UP_MFA, or DENY
    """
    telemetry_dict = payload.model_dump()
    result = scorer.evaluate_request(telemetry_dict)
    risk_score = result["risk_score"]

    # Apply dynamic thresholds
    if risk_score < policy_thresholds["allow_max_risk"]:
        decision = "ALLOW"
        action_msg = "Explicit trust granted based on low risk. Session token generated."
    elif risk_score <= policy_thresholds["mfa_max_risk"]:
        decision = "STEP_UP_MFA"
        action_msg = "Context uncertainty detected. Multi-Factor Authentication challenge issued."
    else:
        decision = "DENY"
        action_msg = "Zero Trust Violation. Connection rejected; PEP instructed to drop traffic."

    result["decision"] = decision
    result["action_description"] = action_msg

    timestamp_iso = datetime.now(timezone.utc).isoformat()
    session_token = None
    challenge_id = None

    if decision == "ALLOW":
        # Generate short-lived cryptographically signed JWT token
        token_payload = {
            "sub": payload.user_id,
            "role": "authenticated_user",
            "risk_score": risk_score,
            "resource": payload.requested_resource,
            "iat": int(time.time()),
            "exp": int(time.time()) + TOKEN_VALIDITY_SECONDS
        }
        session_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        active_sessions[session_token] = {
            "user_id": payload.user_id,
            "expires_at": time.time() + TOKEN_VALIDITY_SECONDS,
            "risk_score": risk_score
        }

    elif decision == "STEP_UP_MFA":
        challenge_id = f"mfa_{payload.user_id}_{int(time.time())}"
        pending_mfa_challenges[challenge_id] = {
            "user_id": payload.user_id,
            "telemetry": telemetry_dict,
            "risk_score": risk_score,
            "expected_code": "123456",  # Standard demo simulated TOTP code
            "created_at": time.time()
        }

    # Record Audit Log for observation & visual dashboard
    log_entry = {
        "id": len(audit_logs) + 1,
        "timestamp": timestamp_iso,
        "user_id": payload.user_id,
        "source_ip": payload.source_ip,
        "requested_resource": payload.requested_resource,
        "risk_score": risk_score,
        "risk_level": result["risk_level"],
        "decision": decision,
        "risk_factors": result["risk_factors"],
        "action_description": action_msg,
        "token_issued": session_token is not None,
        "challenge_id": challenge_id
    }
    audit_logs.append(log_entry)

    return {
        "status": "success",
        "user_id": payload.user_id,
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": result["risk_level"],
        "risk_factors": result["risk_factors"],
        "session_token": session_token,
        "challenge_id": challenge_id,
        "token_validity_seconds": TOKEN_VALIDITY_SECONDS if session_token else 0,
        "explanation": action_msg
    }

@app.post("/verify-token")
def verify_token(payload: VerifyTokenPayload):
    """
    Called by Policy Enforcement Point (PEP) to cryptographically verify token
    """
    token = payload.token
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if token not in active_sessions:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or untracked.")
        
        return {
            "valid": True,
            "user_id": decoded["sub"],
            "risk_score": decoded.get("risk_score", 0),
            "resource": decoded.get("resource"),
            "expires_in": int(decoded["exp"] - time.time())
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token expired. Per-session re-authentication required.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Cryptographically invalid session token.")

@app.post("/step-up-verify")
def step_up_verify(payload: StepUpPayload):
    """
    Completes MFA verification for Medium Risk requests and issues a valid session token
    """
    challenge = pending_mfa_challenges.get(payload.challenge_id)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or expired MFA challenge.")
    
    if payload.mfa_code != challenge["expected_code"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid MFA verification code.")

    # Successfully verified -> Issue session token
    user_id = challenge["user_id"]
    token_payload = {
        "sub": user_id,
        "role": "authenticated_user",
        "risk_score": challenge["risk_score"],
        "resource": challenge["telemetry"].get("requested_resource", "/api/v1/financial-records"),
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_VALIDITY_SECONDS
    }
    session_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    active_sessions[session_token] = {
        "user_id": user_id,
        "expires_at": time.time() + TOKEN_VALIDITY_SECONDS,
        "risk_score": challenge["risk_score"]
    }
    del pending_mfa_challenges[payload.challenge_id]

    # Update latest audit log
    for entry in reversed(audit_logs):
        if entry.get("challenge_id") == payload.challenge_id:
            entry["decision"] = "STEP_UP_APPROVED"
            entry["action_description"] = "MFA challenge successfully verified. Access granted."
            entry["token_issued"] = True
            break

    return {
        "status": "success",
        "message": "MFA verified successfully. Session token generated.",
        "session_token": session_token,
        "token_validity_seconds": TOKEN_VALIDITY_SECONDS
    }

@app.get("/audit-logs")
def get_audit_logs(limit: int = 50):
    return audit_logs[-limit:]

@app.get("/metrics")
def get_metrics():
    total = len(audit_logs)
    if total == 0:
        return {
            "total_requests": 0,
            "allowed": 0,
            "mfa_challenged": 0,
            "denied": 0,
            "avg_risk_score": 0.0
        }
    
    allowed = sum(1 for a in audit_logs if "ALLOW" in a["decision"])
    mfa = sum(1 for a in audit_logs if "STEP_UP" in a["decision"])
    denied = sum(1 for a in audit_logs if a["decision"] == "DENY")
    avg_risk = sum(a["risk_score"] for a in audit_logs) / total

    return {
        "total_requests": total,
        "allowed": allowed,
        "mfa_challenged": mfa,
        "denied": denied,
        "avg_risk_score": round(avg_risk, 1),
        "policy_thresholds": policy_thresholds
    }

@app.post("/update-thresholds")
def update_thresholds(payload: ThresholdUpdatePayload):
    policy_thresholds["allow_max_risk"] = payload.allow_max_risk
    policy_thresholds["mfa_max_risk"] = payload.mfa_max_risk
    return {
        "status": "success",
        "new_thresholds": policy_thresholds
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("policy_engine:app", host="127.0.0.1", port=8000, reload=False)

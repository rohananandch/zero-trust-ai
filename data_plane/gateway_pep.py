"""
NIST SP 800-207 Data Plane: Policy Enforcement Point (PEP) Gateway
Runs on http://127.0.0.1:8001

Responsibilities:
- Intercepts all subject traffic directed at enterprise resources.
- Interrogates the Control Plane (PE/PA on Port 8000) for dynamic authorization.
- Terminates untrusted connections and drops malicious packets.
- Proxies authorized requests to the Protected Service (Port 8002) with internal credentials.
"""

from fastapi import FastAPI, Request, Header, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import requests

app = FastAPI(
    title="Zero Trust Data Plane (Policy Enforcement Point)",
    description="NIST SP 800-207 PEP Gateway & Identity-Aware Reverse Proxy",
    version="1.0.0"
)

CONTROL_PLANE_URL = "http://127.0.0.1:8000"
PROTECTED_RESOURCE_URL = "http://127.0.0.1:8002"
PEP_SHARED_SECRET = "pep-authenticated-gateway-key-9921"

class GatewayAccessRequest(BaseModel):
    user_id: str
    source_ip: Optional[str] = "192.168.1.10"
    access_time_hour: float = 12.0
    day_of_week: int = 2
    ip_reputation_score: float = 0.05
    geo_distance_km: float = 15.0
    device_posture_score: float = 0.95
    requested_data_mb: float = 20.0
    request_rate_per_min: int = 5
    failed_logins_recent: int = 0
    requested_resource: str = "/api/v1/financial-records"

class GatewayMFASolveRequest(BaseModel):
    challenge_id: str
    mfa_code: str

@app.get("/")
def pep_root():
    return {
        "component": "NIST SP 800-207 Policy Enforcement Point (Data Plane)",
        "port": 8001,
        "status": "ACTIVE_INTERCEPTOR",
        "control_plane_target": CONTROL_PLANE_URL,
        "protected_resource_target": PROTECTED_RESOURCE_URL
    }

@app.post("/gateway/request-access")
def request_access(payload: GatewayAccessRequest):
    """
    Client initiates an access request through the PEP.
    PEP proxies telemetry context to Control Plane Policy Engine for real-time risk assessment.
    """
    try:
        pe_resp = requests.post(
            f"{CONTROL_PLANE_URL}/evaluate-policy",
            json=payload.model_dump(),
            timeout=5.0
        )
        pe_data = pe_resp.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Control Plane Policy Engine unreachable: {str(e)}"
        )

    decision = pe_data.get("decision")
    risk_score = pe_data.get("risk_score", 0)

    if decision == "ALLOW":
        return {
            "gateway_status": "ACCESS_AUTHORIZED",
            "decision": "ALLOW",
            "risk_score": risk_score,
            "risk_level": pe_data.get("risk_level"),
            "session_token": pe_data.get("session_token"),
            "token_validity_seconds": pe_data.get("token_validity_seconds"),
            "instructions": "Pass session_token in 'Authorization: Bearer <token>' header on /gateway/resource/*"
        }
    elif decision == "STEP_UP_MFA":
        return {
            "gateway_status": "STEP_UP_REQUIRED",
            "decision": "STEP_UP_MFA",
            "risk_score": risk_score,
            "risk_level": pe_data.get("risk_level"),
            "risk_factors": pe_data.get("risk_factors"),
            "challenge_id": pe_data.get("challenge_id"),
            "message": "Elevated risk detected. Submit MFA code via /gateway/solve-mfa to proceed."
        }
    else:
        # Zero Trust: DENY
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "gateway_status": "CONNECTION_TERMINATED",
                "decision": "DENY",
                "risk_score": risk_score,
                "risk_level": pe_data.get("risk_level"),
                "risk_factors": pe_data.get("risk_factors"),
                "reason": "Request rejected by Zero Trust Policy Engine due to anomalous risk telemetry."
            }
        )

@app.post("/gateway/solve-mfa")
def solve_mfa(payload: GatewayMFASolveRequest):
    """
    Submits second-factor authentication for medium-risk access requests.
    """
    try:
        pe_resp = requests.post(
            f"{CONTROL_PLANE_URL}/step-up-verify",
            json=payload.model_dump(),
            timeout=5.0
        )
        if pe_resp.status_code != 200:
            raise HTTPException(
                status_code=pe_resp.status_code,
                detail=pe_resp.json().get("detail", "MFA verification failed.")
            )
        return pe_resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/gateway/resource/financial-records")
def proxy_financial_records(authorization: Optional[str] = Header(None)):
    """
    Secure Data Plane Proxy:
    1. Intercepts request to confidential financial records
    2. Validates session token with Control Plane
    3. If valid, forwards to Protected Backend injecting PEP cryptographic assertion
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ZERO TRUST ENFORCEMENT: Missing or malformed Bearer session token. Obtain token via /gateway/request-access."
        )

    token = authorization.split(" ")[1]

    # Verify with Policy Engine
    try:
        verify_resp = requests.post(
            f"{CONTROL_PLANE_URL}/verify-token",
            json={"token": token},
            timeout=5.0
        )
        if verify_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token invalid, expired, or revoked by Control Plane."
            )
        user_info = verify_resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Control plane verification error: {str(e)}")

    # Token is cryptographically valid -> Forward to Protected Backend Resource
    try:
        backend_resp = requests.get(
            f"{PROTECTED_RESOURCE_URL}/api/v1/financial-records",
            headers={
                "X-PEP-Authorization": PEP_SHARED_SECRET,
                "X-Authenticated-User": user_info["user_id"]
            },
            timeout=5.0
        )
        return backend_resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Backend resource unavailable: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway_pep:app", host="127.0.0.1", port=8001, reload=False)

"""
Protected Enterprise Resource: Confidential Financial Records API
Runs on http://127.0.0.1:8002

Zero Trust Tenet: "Assume the network is compromised."
This service NEVER implicitly trusts connections from localhost or internal IP.
It strictly mandates a cryptographically verified 'X-PEP-Authorization' header
proving that the request was inspected and cleared by the Policy Enforcement Point (PEP).
"""

from fastapi import FastAPI, Header, HTTPException, status
from typing import Optional

app = FastAPI(
    title="Protected Enterprise Resource (Data Plane Target)",
    description="Confidential Enterprise Database with Strict Zero-Trust Enforcement",
    version="1.0.0"
)

# Simulated confidential dataset
CONFIDENTIAL_VAULT = [
    {"account_id": "ACC-90412", "client_name": "Acme Corp", "balance_usd": 14_250_000.00, "tier": "Enterprise Secret"},
    {"account_id": "ACC-58210", "client_name": "Globex International", "balance_usd": 8_920_500.50, "tier": "Enterprise Secret"},
    {"account_id": "ACC-31415", "client_name": "Initech Systems", "balance_usd": 3_450_000.00, "tier": "Confidential"},
    {"account_id": "ACC-88392", "client_name": "Umbrella Bio-Tech", "balance_usd": 42_100_000.00, "tier": "Top Secret"},
    {"account_id": "ACC-71934", "client_name": "Cyberdyne Defense", "balance_usd": 65_800_000.00, "tier": "Top Secret"}
]

PEP_SHARED_SECRET = "pep-authenticated-gateway-key-9921"

@app.get("/")
def resource_root():
    return {
        "service": "Protected Confidential Resource Server",
        "port": 8002,
        "security_policy": "Zero Trust - Direct Access Restricted",
        "status": "SECURED"
    }

@app.get("/api/v1/financial-records")
def get_financial_records(
    x_pep_authorization: Optional[str] = Header(None),
    x_authenticated_user: Optional[str] = Header(None)
):
    """
    Protected sensitive endpoint.
    Only allows access if passed through the Policy Enforcement Point (PEP)
    with valid gateway credentials.
    """
    if not x_pep_authorization or x_pep_authorization != PEP_SHARED_SECRET:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "ZERO TRUST SECURITY VIOLATION: Direct backend resource access is strictly forbidden! "
                "Packet rejected. All traffic must be mediated and verified by the Policy Enforcement Point (PEP)."
            )
        )

    return {
        "status": "ACCESS_GRANTED",
        "requester": x_authenticated_user or "unknown",
        "classification": "CONFIDENTIAL ENTERPRISE ASSET",
        "records_count": len(CONFIDENTIAL_VAULT),
        "data": CONFIDENTIAL_VAULT
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("secure_api:app", host="127.0.0.1", port=8002, reload=False)

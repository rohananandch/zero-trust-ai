"""
Automated Integration Tests for Zero Trust AI Architecture
Verifies Risk Scoring, Policy Engine decisions, JWT verification, and Protected Resource defense.
"""

import unittest
from fastapi.testclient import TestClient
from control_plane.policy_engine import app as pe_app, active_sessions
from protected_service.secure_api import app as vault_app
from models.risk_scorer import ZeroTrustRiskScorer

class TestZeroTrustArchitecture(unittest.TestCase):
    def setUp(self):
        self.pe_client = TestClient(pe_app)
        self.vault_client = TestClient(vault_app)
        self.scorer = ZeroTrustRiskScorer()

    def test_01_risk_scorer_alice_low_risk(self):
        """Alice: normal office hours, clean IP, trusted device -> ALLOW (< 35)"""
        res = self.scorer.evaluate_request({
            "access_time_hour": 11.0,
            "day_of_week": 2,
            "ip_reputation_score": 0.02,
            "geo_distance_km": 10.0,
            "device_posture_score": 0.95,
            "requested_data_mb": 15.0,
            "request_rate_per_min": 5,
            "failed_logins_recent": 0
        })
        self.assertEqual(res["decision"], "ALLOW")
        self.assertLess(res["risk_score"], 35)

    def test_02_risk_scorer_eve_high_risk(self):
        """Eve: 3 AM, foreign IP, rogue device, bulk exfiltration -> DENY (> 65)"""
        res = self.scorer.evaluate_request({
            "access_time_hour": 3.0,
            "day_of_week": 4,
            "ip_reputation_score": 0.90,
            "geo_distance_km": 8000.0,
            "device_posture_score": 0.20,
            "requested_data_mb": 5000.0,
            "request_rate_per_min": 75,
            "failed_logins_recent": 6
        })
        self.assertEqual(res["decision"], "DENY")
        self.assertGreater(res["risk_score"], 65)
        self.assertGreater(len(res["risk_factors"]), 2)

    def test_03_policy_engine_allow_issues_token(self):
        """Control Plane /evaluate-policy returns token for legitimate request"""
        resp = self.pe_client.post("/evaluate-policy", json={
            "user_id": "alice_test",
            "source_ip": "192.168.1.100",
            "access_time_hour": 13.0,
            "day_of_week": 1,
            "ip_reputation_score": 0.01,
            "geo_distance_km": 5.0,
            "device_posture_score": 0.98,
            "requested_data_mb": 12.0,
            "request_rate_per_min": 4,
            "failed_logins_recent": 0,
            "requested_resource": "/api/v1/financial-records"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertIsNotNone(data["session_token"])

        # Verify token endpoint
        verify_resp = self.pe_client.post("/verify-token", json={"token": data["session_token"]})
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.json()["valid"])
        self.assertEqual(verify_resp.json()["user_id"], "alice_test")

    def test_04_policy_engine_step_up_mfa(self):
        """Control Plane issues challenge for medium risk and approves after valid OTP"""
        resp = self.pe_client.post("/evaluate-policy", json={
            "user_id": "bob_test",
            "source_ip": "172.16.1.10",
            "access_time_hour": 21.0,
            "day_of_week": 2,
            "ip_reputation_score": 0.18,
            "geo_distance_km": 90.0,
            "device_posture_score": 0.65,
            "requested_data_mb": 40.0,
            "request_rate_per_min": 7,
            "failed_logins_recent": 1,
            "requested_resource": "/api/v1/financial-records"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "STEP_UP_MFA")
        self.assertIsNotNone(data["challenge_id"])

        # Submit OTP to step-up-verify
        mfa_resp = self.pe_client.post("/step-up-verify", json={
            "challenge_id": data["challenge_id"],
            "mfa_code": "123456"
        })
        self.assertEqual(mfa_resp.status_code, 200)
        self.assertIsNotNone(mfa_resp.json()["session_token"])

    def test_05_protected_vault_direct_access_blocked(self):
        """Backend resource blocks direct requests that bypass PEP"""
        resp = self.vault_client.get("/api/v1/financial-records")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("ZERO TRUST SECURITY VIOLATION", resp.json()["detail"])

    def test_06_protected_vault_pep_authorized_access(self):
        """Backend resource grants access when PEP assertion header is present"""
        resp = self.vault_client.get(
            "/api/v1/financial-records",
            headers={
                "X-PEP-Authorization": "pep-authenticated-gateway-key-9921",
                "X-Authenticated-User": "alice_test"
            }
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ACCESS_GRANTED")
        self.assertEqual(resp.json()["requester"], "alice_test")

if __name__ == "__main__":
    unittest.main()

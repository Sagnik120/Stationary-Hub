import pytest
from rate_limiter import limiter
import db_helper


def test_complete_forgot_and_reset_password_workflow(client, sample_user):
    """
    End-to-End Forgot Password Cycle:
    1. Request reset token for sample_user
    2. Verify token is active and valid
    3. Reset password to new strong password
    4. Verify old password no longer works (401)
    5. Verify new password logs in successfully (200)
    """
    limiter.reset()

    # Step 1: Request reset
    req_resp = client.post("/api/auth/forgot-password", json={"email": sample_user["email"]})
    assert req_resp.status_code == 200
    token = req_resp.json()["reset_token"]

    # Step 2: Verify reset token
    verify_resp = client.post("/api/auth/verify-reset-token", json={"token": token})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True
    assert verify_resp.json()["email"].lower() == sample_user["email"].lower()

    # Step 3: Reset password
    new_password = "BrandNewSecurePassword2026!#"
    reset_resp = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": new_password
    })
    assert reset_resp.status_code == 200
    assert "successful" in reset_resp.json()["message"].lower()

    # Step 4: Login with old password must FAIL
    old_login = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": sample_user["password"]
    })
    assert old_login.status_code == 401

    # Step 5: Login with new password must SUCCEED
    new_login = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": new_password
    })
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()

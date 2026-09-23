import pytest
from rate_limiter import limiter
import db_helper
import security


def test_anti_enumeration_nonexistent_email(client):
    """
    OWASP Recommendation:
    Requesting password reset for a non-existent email must return the exact same
    generic success message without disclosing whether the account exists.
    """
    limiter.reset()
    resp = client.post("/api/auth/forgot-password", json={"email": "nobody_exists_here_999@example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "If an account with this email exists" in data["message"]
    # Ensure no reset_token is exposed for fake email
    assert "reset_token" not in data


def test_tampered_reset_token_rejected(client, sample_user):
    """Verifies that an altered or fabricated reset token is rejected."""
    limiter.reset()
    resp = client.post("/api/auth/verify-reset-token", json={"token": "completely_fake_tampered_token_xyz"})
    assert resp.status_code == 400
    assert "invalid, expired" in resp.json()["detail"].lower()


def test_reset_token_replay_rejected(client, sample_user):
    """
    Verifies that a reset token CANNOT be used more than once.
    Replay attempts must be strictly rejected.
    """
    limiter.reset()
    # 1. Request token
    req_resp = client.post("/api/auth/forgot-password", json={"email": sample_user["email"]})
    assert req_resp.status_code == 200
    token = req_resp.json()["reset_token"]

    # 2. First reset succeeds
    new_pw = "BrandNewPassword123!"
    reset_resp = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": new_pw
    })
    assert reset_resp.status_code == 200

    # 3. Second attempt with same token MUST fail (replay attack defense)
    replay_resp = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "AnotherPassword999!"
    })
    assert replay_resp.status_code == 400
    assert "failed" in replay_resp.json()["detail"].lower()

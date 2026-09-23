import pytest
from rate_limiter import limiter


def test_forgot_password_rate_limiting(client, sample_user):
    """
    Verifies that requesting forgot password tokens is rate-limited
    to prevent spamming and email flooding.
    """
    limiter.reset()

    # Max 3 attempts allowed
    for _ in range(3):
        r = client.post("/api/auth/forgot-password", json={"email": sample_user["email"]})
        assert r.status_code == 200

    # 4th attempt must be rejected with 429 Too Many Requests
    blocked = client.post("/api/auth/forgot-password", json={"email": sample_user["email"]})
    assert blocked.status_code == 429
    assert "rate limit exceeded" in blocked.json()["detail"].lower()


@pytest.mark.parametrize("weak_password", [
    "short1!",
    "alllowercasenouppercase1!",
    "ALLUPPERCASENOLOWERCASE1!",
    "NoDigitsInPassword!",
    "NoSpecialSymbols123"
])
def test_reset_password_weak_passwords_rejected(client, sample_user, weak_password):
    """Verifies that new passwords in reset flow must strictly meet complexity criteria."""
    limiter.reset()

    # Request valid token
    req = client.post("/api/auth/forgot-password", json={"email": sample_user["email"]})
    token = req.json()["reset_token"]

    # Attempt reset with weak password
    resp = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": weak_password
    })
    assert resp.status_code in (400, 422)
    detail_str = str(resp.json()["detail"]).lower()
    assert "password" in detail_str or "length" in detail_str or "string_too_short" in detail_str


def test_reset_password_blank_token_rejected(client):
    """Verifies that a blank or whitespace reset token is rejected with 422 or 400."""
    limiter.reset()
    resp = client.post("/api/auth/reset-password", json={
        "token": "",
        "new_password": "ValidPassword123!"
    })
    assert resp.status_code == 422

import pytest
from rate_limiter import limiter
import security


def test_oauth_callback_missing_state_rejected(client):
    """Verifies that OAuth callback requests lacking a valid state parameter are rejected with 400."""
    limiter.reset()
    resp = client.post("/api/auth/oauth/google/callback", json={
        "code": "sample_auth_code",
        "mock_profile": {"email": "hacker@example.com", "name": "Hacker"}
    })
    assert resp.status_code == 400
    assert "state parameter" in resp.json()["detail"].lower()


def test_oauth_callback_tampered_state_rejected(client):
    """Verifies that an altered state parameter triggers CSRF defense rejection."""
    limiter.reset()
    # Legitimate state generated
    security.generate_oauth_state("github")

    resp = client.post("/api/auth/oauth/github/callback", json={
        "state": "forged_state_token_12345",
        "mock_profile": {"email": "user@example.com", "name": "Legit"}
    })
    assert resp.status_code == 400
    assert "csrf" in resp.json()["detail"].lower()


def test_oauth_state_cannot_be_replayed(client):
    """Verifies that a consumed state token cannot be replayed."""
    limiter.reset()
    state = security.generate_oauth_state("google")

    payload = {
        "state": state,
        "mock_profile": {"email": "replayed_user@example.com", "name": "Replay User"}
    }

    # First call succeeds
    resp1 = client.post("/api/auth/oauth/google/callback", json=payload)
    assert resp1.status_code == 200

    # Second call with same state MUST fail with 400 (replay attack rejected)
    resp2 = client.post("/api/auth/oauth/google/callback", json=payload)
    assert resp2.status_code == 400

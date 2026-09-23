import pytest
from rate_limiter import limiter


def test_rate_limiting_login_burst(client, sample_user):
    """
    Simulates a brute-force credential stuffing attack against /api/auth/login.
    Allowed limit: 5 requests. The 6th request must trigger HTTP 429.
    """
    limiter.reset()

    # Send 5 attempts (allowed)
    for i in range(5):
        resp = client.post("/api/auth/login", json={
            "email": sample_user["email"],
            "password": "WrongPasswordAttempt!"
        })
        assert resp.status_code == 401
        assert "X-RateLimit-Remaining" in resp.headers

    # 6th attempt must be blocked by rate limiter!
    blocked_resp = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": "WrongPasswordAttempt!"
    })
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert int(blocked_resp.headers["Retry-After"]) >= 1
    assert "Rate limit exceeded" in blocked_resp.json()["detail"]


def test_rate_limiting_register_burst(client):
    """
    Simulates automated registration bot burst against /api/auth/register.
    Allowed limit: 3 requests. 4th request must trigger HTTP 429.
    """
    limiter.reset()

    for i in range(3):
        resp = client.post("/api/auth/register", json={
            "name": f"User {i}",
            "email": f"botuser_{i}@example.com",
            "password": "StrongPassword123!"
        })
        assert resp.status_code == 201

    # 4th attempt must be blocked
    blocked_resp = client.post("/api/auth/register", json={
        "name": "Bot User 4",
        "email": "botuser_4@example.com",
        "password": "StrongPassword123!"
    })
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert blocked_resp.headers["X-RateLimit-Remaining"] == "0"


def test_rate_limiter_reset(client, sample_user):
    """Verifies that resetting limiter state clears blocked clients."""
    limiter.reset()
    for _ in range(5):
        client.post("/api/auth/login", json={
            "email": sample_user["email"],
            "password": "WrongPassword!"
        })

    # Trigger 429
    blocked = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": "WrongPassword!"
    })
    assert blocked.status_code == 429

    # Reset
    limiter.reset()
    resumed = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": "WrongPassword!"
    })
    assert resumed.status_code == 401, "After reset, requests should be evaluated freshly"

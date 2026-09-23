import pytest


def test_complete_auth_lifecycle(client):
    """
    End-to-End integration test of the full authentication lifecycle:
    Registration -> Protected Profile -> Login -> Refresh -> Logout -> Verify Invalidation
    """
    user_data = {
        "name": "Integration User",
        "email": "integration@stationaryhub.com",
        "password": "SecurePassword2026!"
    }

    # 1. Register
    reg_resp = client.post("/api/auth/register", json=user_data)
    assert reg_resp.status_code == 201
    tokens = reg_resp.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 2. Access protected endpoint /api/auth/me with access_token
    auth_headers = {"Authorization": f"Bearer {access_token}"}
    me_resp = client.get("/api/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    profile = me_resp.json()
    assert profile["email"] == user_data["email"]
    assert profile["name"] == user_data["name"]

    # 3. Access without token should be rejected
    unauth_resp = client.get("/api/auth/me")
    assert unauth_resp.status_code == 401

    # 4. Login with registered credentials
    login_resp = client.post("/api/auth/login", json={
        "email": user_data["email"],
        "password": user_data["password"]
    })
    assert login_resp.status_code == 200
    new_login_tokens = login_resp.json()
    new_access = new_login_tokens["access_token"]
    new_refresh = new_login_tokens["refresh_token"]

    # 5. Refresh token
    refresh_resp = client.post("/api/auth/refresh", json={"refresh_token": new_refresh})
    assert refresh_resp.status_code == 200
    refreshed_tokens = refresh_resp.json()
    latest_access = refreshed_tokens["access_token"]
    latest_refresh = refreshed_tokens["refresh_token"]

    # 6. Verify latest access token works
    latest_me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {latest_access}"})
    assert latest_me_resp.status_code == 200

    # 7. Logout
    logout_resp = client.post("/api/auth/logout", json={"refresh_token": latest_refresh})
    assert logout_resp.status_code == 200

    # 8. Verify revoked refresh token can no longer be used
    revoked_resp = client.post("/api/auth/refresh", json={"refresh_token": latest_refresh})
    assert revoked_resp.status_code == 401

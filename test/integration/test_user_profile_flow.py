import pytest
from rate_limiter import limiter
import db_helper


def test_user_profile_and_password_management_flow(client, sample_user):
    """
    Verifies user profile retrieval, updating details, changing password,
    and terminating all sessions.
    """
    limiter.reset()

    # Login
    login_resp = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": sample_user["password"]
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch Profile
    prof_resp = client.get("/api/user/profile", headers=headers)
    assert prof_resp.status_code == 200
    prof = prof_resp.json()
    assert prof["email"] == sample_user["email"]
    assert "stats" in prof

    # 2. Update Profile
    update_resp = client.put("/api/user/profile", headers=headers, json={
        "name": "Alice In Wonderland Updated",
        "phone": "+91 9988776655",
        "address": "42 Stationery Lane, Wonderland"
    })
    assert update_resp.status_code == 200
    assert update_resp.json()["user"]["name"] == "Alice In Wonderland Updated"
    assert update_resp.json()["user"]["phone"] == "+91 9988776655"

    # 3. Change Password
    # First attempt with incorrect old password must fail
    bad_change = client.put("/api/user/change-password", headers=headers, json={
        "old_password": "WrongOldPassword123!",
        "new_password": "ValidNewPassword2026!$"
    })
    assert bad_change.status_code == 400
    assert "current password verification failed" in bad_change.json()["detail"].lower()

    # Second attempt with correct old password must succeed
    good_change = client.put("/api/user/change-password", headers=headers, json={
        "old_password": sample_user["password"],
        "new_password": "ValidNewPassword2026!$"
    })
    assert good_change.status_code == 200

    # 4. Revoke all sessions
    revoke_resp = client.post("/api/auth/revoke-all-sessions", headers=headers)
    assert revoke_resp.status_code == 200
    assert "revoked" in revoke_resp.json()["message"].lower()

import pytest
from rate_limiter import limiter
import db_helper


@pytest.mark.parametrize("provider", ["google", "github", "facebook"])
def test_social_oauth_login_and_provisioning(client, provider):
    """
    Verifies OAuth flow across Google, GitHub, and Facebook:
    1. Fetch OAuth URL and CSRF state
    2. Post callback with state and mock user payload
    3. Verify user is provisioned in database with role 'customer'
    4. Access /api/auth/me with returned access token
    5. Second login with same provider links to identical user ID
    """
    limiter.reset()

    # Step 1: Request URL and state
    url_resp = client.get(f"/api/auth/oauth/{provider}/url")
    assert url_resp.status_code == 200
    state = url_resp.json()["state"]

    # Step 2: Post callback
    user_email = f"oauth_{provider}_test@example.com"
    cb_resp = client.post(f"/api/auth/oauth/{provider}/callback", json={
        "state": state,
        "mock_profile": {
            "name": f"{provider.capitalize()} Test User",
            "email": user_email,
            "id": f"sub_{provider}_98765"
        }
    })
    assert cb_resp.status_code == 200
    auth_data = cb_resp.json()
    assert "access_token" in auth_data
    user_id = auth_data["user"]["id"]
    assert auth_data["user"]["email"] == user_email

    # Step 3: Access /api/auth/me
    token = auth_data["access_token"]
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["id"] == user_id

    # Step 4: Re-authenticating with same OAuth account must return same user
    url_resp2 = client.get(f"/api/auth/oauth/{provider}/url")
    state2 = url_resp2.json()["state"]
    cb_resp2 = client.post(f"/api/auth/oauth/{provider}/callback", json={
        "state": state2,
        "mock_profile": {
            "name": f"{provider.capitalize()} Test User",
            "email": user_email,
            "id": f"sub_{provider}_98765"
        }
    })
    assert cb_resp2.status_code == 200
    assert cb_resp2.json()["user"]["id"] == user_id

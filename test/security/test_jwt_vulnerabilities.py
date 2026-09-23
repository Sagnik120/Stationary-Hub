import pytest
import jwt
from datetime import datetime, timezone, timedelta

import security
import config


def test_jwt_none_algorithm_attack():
    """
    Simulates the critical 'none' algorithm exploit where an attacker strips the signature.
    Must be blocked by strict algorithm enforcement.
    """
    payload = {
        "sub": "1",
        "email": "admin@stationaryhub.com",
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "jti": "attack_none_jti",
        "token_type": "access"
    }
    # Create unsigned token with alg: none
    unsigned_token = jwt.encode(payload, key=None, algorithm=None)

    with pytest.raises(Exception):
        security.decode_token(unsigned_token, is_refresh=False)


def test_jwt_wrong_secret_key():
    """Token signed with an attacker's rogue secret key must be rejected."""
    rogue_secret = "attacker_evil_secret_key_1234567890"
    payload = {
        "sub": "1",
        "email": "user@example.com",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "jti": "rogue_jti",
        "token_type": "access"
    }
    rogue_token = jwt.encode(payload, rogue_secret, algorithm="HS256")

    with pytest.raises(Exception):
        security.decode_token(rogue_token, is_refresh=False)


def test_jwt_tampered_payload_claims():
    """
    An attacker takes a valid token, changes role to 'admin', and reassembles token.
    Must fail signature verification.
    """
    token = security.create_access_token({"sub": "1", "role": "customer"})
    parts = token.split(".")
    # Modify payload (change customer to admin)
    import base64, json
    # Pad base64
    payload_str = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_str))
    claims["role"] = "admin"
    new_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    tampered_token = f"{parts[0]}.{new_payload}.{parts[2]}"

    with pytest.raises(Exception):
        security.decode_token(tampered_token, is_refresh=False)


def test_jwt_missing_required_claims():
    """Tokens missing standard required claims (sub, exp, jti) must be rejected."""
    incomplete_payload = {"role": "admin"}
    token = jwt.encode(incomplete_payload, config.JWT_SECRET_KEY, algorithm="HS256")

    with pytest.raises(Exception):
        security.decode_token(token, is_refresh=False)


def test_refresh_token_replay_attack_revocation(client, sample_user):
    """
    Tests token rotation and replay detection:
    1. Login to obtain access + refresh token.
    2. Refresh token once (succeeds, returns new pair).
    3. Attempt to reuse old refresh token (REPLAY ATTACK).
    4. Must return 401 AND invalidate user's session tokens.
    """
    # 1. Login
    login_resp = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": sample_user["password"]
    })
    assert login_resp.status_code == 200
    first_refresh = login_resp.json()["refresh_token"]

    # 2. Refresh token (valid rotation)
    refresh_resp1 = client.post("/api/auth/refresh", json={"refresh_token": first_refresh})
    assert refresh_resp1.status_code == 200
    second_refresh = refresh_resp1.json()["refresh_token"]

    # 3. Replay attack: try to reuse first_refresh
    replay_resp = client.post("/api/auth/refresh", json={"refresh_token": first_refresh})
    assert replay_resp.status_code == 401
    assert "invalid or has already been used" in replay_resp.json()["detail"].lower()

    # 4. Token reuse detection must have revoked second_refresh as well!
    cascade_check = client.post("/api/auth/refresh", json={"refresh_token": second_refresh})
    assert cascade_check.status_code == 401, "Replay attack should cascade revocation to protect user family!"

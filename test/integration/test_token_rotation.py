import pytest


def test_sequential_token_rotation(client, sample_user):
    """
    Tests sequential refresh token rotation:
    Token0 -> Token1 -> Token2 -> Token3
    Verifies that Token0, Token1, and Token2 are all invalid once rotated.
    """
    login_resp = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": sample_user["password"]
    })
    assert login_resp.status_code == 200
    token0 = login_resp.json()["refresh_token"]

    # Rotation 1
    resp1 = client.post("/api/auth/refresh", json={"refresh_token": token0})
    assert resp1.status_code == 200
    token1 = resp1.json()["refresh_token"]

    # Rotation 2
    resp2 = client.post("/api/auth/refresh", json={"refresh_token": token1})
    assert resp2.status_code == 200
    token2 = resp2.json()["refresh_token"]

    # Rotation 3
    resp3 = client.post("/api/auth/refresh", json={"refresh_token": token2})
    assert resp3.status_code == 200
    token3 = resp3.json()["refresh_token"]

    # Verify that token0, token1, and token2 fail if attempted
    for old_token in [token0, token1, token2]:
        old_resp = client.post("/api/auth/refresh", json={"refresh_token": old_token})
        assert old_resp.status_code == 401

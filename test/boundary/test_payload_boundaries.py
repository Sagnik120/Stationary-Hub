import pytest


def test_extremely_large_payload_rejected(client):
    """Submits 50,000 character oversized inputs to verify DDoS/buffer safety."""
    huge_string = "A" * 50000
    resp = client.post("/api/auth/register", json={
        "name": huge_string,
        "email": "huge@example.com",
        "password": "Password123!"
    })
    # Must reject with 422 Unprocessable Entity
    assert resp.status_code == 422


def test_empty_string_payloads(client):
    """Submits empty strings in required fields."""
    resp = client.post("/api/auth/register", json={
        "name": "",
        "email": "",
        "password": ""
    })
    assert resp.status_code == 422


def test_null_bytes_in_input(client):
    """Submits null bytes (poison null byte attack)."""
    resp = client.post("/api/auth/register", json={
        "name": "User\x00Injected",
        "email": "nullbyte@example.com",
        "password": "Password123!"
    })
    # Should either sanitize, process safely without truncation, or reject
    assert resp.status_code in (201, 400, 422)


def test_unicode_and_emojis(client):
    """Verifies that international Unicode and emojis are handled properly."""
    unicode_user = {
        "name": "Stationery 🚀 筆記本",
        "email": "unicode_user@domain.com",
        "password": "Password123!#🚀"
    }
    resp = client.post("/api/auth/register", json=unicode_user)
    assert resp.status_code == 201
    assert "access_token" in resp.json()

    # Login with the unicode credentials
    login_resp = client.post("/api/auth/login", json={
        "email": unicode_user["email"],
        "password": unicode_user["password"]
    })
    assert login_resp.status_code == 200


def test_negative_order_id_boundary(client):
    """Order ID must be strictly positive."""
    for bad_id in [0, -1, -9999]:
        resp = client.post("/api/orders/track", json={"order_id": bad_id})
        assert resp.status_code == 422, f"Should reject negative/zero order_id: {bad_id}"

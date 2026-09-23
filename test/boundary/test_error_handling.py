import pytest


def test_malformed_json_handling(client):
    """Sends raw syntactically invalid JSON string."""
    resp = client.post(
        "/api/auth/login",
        content="{\"email\": \"test@example.com\", \"password\": ",
        headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 422


def test_method_not_allowed(client):
    """Sends GET request to POST-only authentication endpoint."""
    resp = client.get("/api/auth/login")
    assert resp.status_code == 405


def test_nonexistent_endpoint_returns_404(client):
    """Sends request to non-existent route."""
    resp = client.get("/api/nonexistent/route")
    assert resp.status_code == 404


def test_extra_fields_in_payload_ignored_safely(client):
    """Extra unexpected payload fields should be ignored safely."""
    payload = {
        "name": "Extra Fields User",
        "email": "extra_fields@example.com",
        "password": "Password123!",
        "admin": True,
        "role": "superadmin",
        "hacker_field": "drop_tables"
    }
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201
    user = resp.json()["user"]
    # Role must still be customer, malicious extra fields ignored
    assert user["role"] == "customer"

import pytest
from rate_limiter import limiter


def test_order_empty_items_rejected(client, sample_user):
    """Verifies that an order with empty items list is rejected."""
    limiter.reset()
    login = client.post("/api/auth/login", json={"email": sample_user["email"], "password": sample_user["password"]})
    token = login.json()["access_token"]

    resp = client.post("/api/user/orders", headers={"Authorization": f"Bearer {token}"}, json={"items": []})
    assert resp.status_code == 422


def test_order_nonexistent_item_rejected(client, sample_user):
    """Verifies that an order containing an unrecognized item is rejected with 400."""
    limiter.reset()
    login = client.post("/api/auth/login", json={"email": sample_user["email"], "password": sample_user["password"]})
    token = login.json()["access_token"]

    resp = client.post("/api/user/orders", headers={"Authorization": f"Bearer {token}"}, json={
        "items": [{"item_name": "quantum_computer", "quantity": 1}]
    })
    assert resp.status_code == 400
    assert "not available in our stationery catalog" in resp.json()["detail"]


@pytest.mark.parametrize("invalid_qty", [0, -1, -50, 101, 500])
def test_order_invalid_quantity_rejected(client, sample_user, invalid_qty):
    """Verifies that quantities <= 0 or > 100 are rejected by validation constraints."""
    limiter.reset()
    login = client.post("/api/auth/login", json={"email": sample_user["email"], "password": sample_user["password"]})
    token = login.json()["access_token"]

    resp = client.post("/api/user/orders", headers={"Authorization": f"Bearer {token}"}, json={
        "items": [{"item_name": "pen", "quantity": invalid_qty}]
    })
    assert resp.status_code == 422


@pytest.mark.parametrize("bad_id", [0, -99, 9999999])
def test_order_boundary_ids_handled_safely(client, sample_user, bad_id):
    """Verifies that boundary order IDs (zero, negative, very large) return 404 cleanly without 500 errors."""
    limiter.reset()
    login = client.post("/api/auth/login", json={"email": sample_user["email"], "password": sample_user["password"]})
    token = login.json()["access_token"]

    resp = client.get(f"/api/user/orders/{bad_id}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404

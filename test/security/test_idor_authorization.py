import pytest
from rate_limiter import limiter
import db_helper
import security


def test_unauthenticated_user_endpoints_rejected(client):
    """Verifies that endpoints under /api/user/* require valid Bearer authentication."""
    assert client.get("/api/user/profile").status_code == 401
    assert client.get("/api/user/orders").status_code == 401
    assert client.post("/api/user/orders", json={"items": [{"item_name": "pen", "quantity": 1}]}).status_code == 401
    assert client.post("/api/auth/revoke-all-sessions").status_code == 401


def test_idor_cannot_view_other_users_order(client, sample_user, admin_user):
    """
    IDOR Security Test:
    User A places an order.
    User B attempts to fetch User A's order details using User A's order_id.
    Must return 404 Not Found (or 403) and must NEVER reveal User A's items or address.
    """
    limiter.reset()

    # Create Order as Alice (sample_user)
    alice_order_id = db_helper.create_user_order(
        sample_user["user_id"],
        [{"item_name": "notebook", "quantity": 3}, {"item_name": "pen", "quantity": 5}]
    )

    # Login as Bob (admin_user acting as another user)
    bob_login = client.post("/api/auth/login", json={
        "email": admin_user["email"],
        "password": admin_user["password"]
    })
    bob_token = bob_login.json()["access_token"]

    # Bob attempts to view Alice's order
    resp = client.get(
        f"/api/user/orders/{alice_order_id}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_idor_cannot_cancel_other_users_order(client, sample_user, admin_user):
    """
    IDOR Security Test:
    User B cannot cancel an order placed by User A.
    """
    limiter.reset()

    # Alice's order
    alice_order_id = db_helper.create_user_order(
        sample_user["user_id"],
        [{"item_name": "stapler", "quantity": 1}]
    )

    # Bob logs in
    bob_login = client.post("/api/auth/login", json={
        "email": admin_user["email"],
        "password": admin_user["password"]
    })
    bob_token = bob_login.json()["access_token"]

    # Bob attempts to cancel Alice's order
    cancel_resp = client.post(
        f"/api/user/orders/{alice_order_id}/cancel",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert cancel_resp.status_code == 400

    # Verify Alice's order is STILL 'In Progress'
    status = db_helper.get_order_status(alice_order_id)
    assert status == "In Progress"


def test_idor_cannot_reorder_other_users_order(client, sample_user, admin_user):
    """
    IDOR Security Test:
    User B cannot duplicate or clone User A's order items.
    """
    limiter.reset()

    alice_order_id = db_helper.create_user_order(
        sample_user["user_id"],
        [{"item_name": "ruler", "quantity": 2}]
    )

    # Bob logs in
    bob_login = client.post("/api/auth/login", json={
        "email": admin_user["email"],
        "password": admin_user["password"]
    })
    bob_token = bob_login.json()["access_token"]

    reorder_resp = client.post(
        f"/api/user/orders/{alice_order_id}/reorder",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert reorder_resp.status_code == 404

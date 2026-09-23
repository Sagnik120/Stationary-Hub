import pytest
from rate_limiter import limiter
import db_helper


def test_customer_order_lifecycle_flow(client, sample_user):
    """
    Verifies the customer order lifecycle:
    1. Create an order with items (notebook, pen, ruler)
    2. List user orders and verify status is 'In Progress'
    3. View itemized order details
    4. Cancel the order and verify status updates to 'Cancelled'
    5. Reorder the cancelled items and verify a new order ID is created
    """
    limiter.reset()

    # Login
    login_resp = client.post("/api/auth/login", json={
        "email": sample_user["email"],
        "password": sample_user["password"]
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create order
    create_resp = client.post("/api/user/orders", headers=headers, json={
        "items": [
            {"item_name": "notebook", "quantity": 2},
            {"item_name": "pen", "quantity": 3},
            {"item_name": "ruler", "quantity": 1}
        ]
    })
    assert create_resp.status_code == 201
    order_id = create_resp.json()["order_id"]

    # 2. List orders
    list_resp = client.get("/api/user/orders", headers=headers)
    assert list_resp.status_code == 200
    orders = list_resp.json()["orders"]
    matching = [o for o in orders if o["order_id"] == order_id]
    assert len(matching) == 1
    assert matching[0]["status"] == "In Progress"
    assert matching[0]["item_count"] == 3
    # 2*80 + 3*5 + 1*20 = 160 + 15 + 20 = 195.0
    assert matching[0]["total_price"] == 195.0

    # 3. View detail
    detail_resp = client.get(f"/api/user/orders/{order_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["order_id"] == order_id
    assert len(detail["items"]) == 3

    # 4. Cancel order
    cancel_resp = client.post(f"/api/user/orders/{order_id}/cancel", headers=headers)
    assert cancel_resp.status_code == 200
    assert "cancelled" in cancel_resp.json()["message"].lower()

    # Re-check status
    updated_detail = client.get(f"/api/user/orders/{order_id}", headers=headers).json()
    assert updated_detail["status"] == "Cancelled"

    # Attempting to cancel an already-cancelled order must fail
    double_cancel = client.post(f"/api/user/orders/{order_id}/cancel", headers=headers)
    assert double_cancel.status_code == 400

    # 5. Reorder
    reorder_resp = client.post(f"/api/user/orders/{order_id}/reorder", headers=headers)
    assert reorder_resp.status_code == 200
    new_order_id = reorder_resp.json()["new_order_id"]
    assert new_order_id != order_id

    # Verify new order is 'In Progress' with identical total
    new_order_detail = client.get(f"/api/user/orders/{new_order_id}", headers=headers).json()
    assert new_order_detail["status"] == "In Progress"
    assert new_order_detail["total_price"] == 195.0

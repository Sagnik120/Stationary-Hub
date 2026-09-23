import pytest
import db_helper


def test_order_creation_and_tracking_flow(client):
    """
    Tests parameterized order insertion, pricing, and tracking.
    """
    order_id = db_helper.get_next_order_id()
    assert order_id >= 1

    # Insert items
    rc1 = db_helper.insert_order_item("notebook", 2, order_id)
    assert rc1 == 1
    rc2 = db_helper.insert_order_item("pen", 3, order_id)
    assert rc2 == 1

    # Verify total price (2 notebooks * 80 + 3 pens * 5 = 160 + 15 = 175)
    total = db_helper.get_total_order_price(order_id)
    assert total == 175.0

    # Insert tracking status
    db_helper.insert_order_tracking(order_id, "processing")
    status = db_helper.get_order_status(order_id)
    assert status == "processing"

    # API tracking endpoint
    api_resp = client.post("/api/orders/track", json={"order_id": order_id})
    assert api_resp.status_code == 200
    assert api_resp.json()["status"] == "processing"


def test_order_tracking_nonexistent_order(client):
    api_resp = client.post("/api/orders/track", json={"order_id": 9999999})
    assert api_resp.status_code == 404


def test_dialogflow_webhook_order_flow(client):
    """
    Tests Dialogflow chatbot webhook end-to-end.
    """
    session_id = "test_session_12345"
    context_name = f"projects/stationary-hub/agent/sessions/{session_id}/contexts/ongoing-order"

    # 1. Add item
    add_payload = {
        "queryResult": {
            "intent": {"displayName": "order.add - context: ongoing-order"},
            "parameters": {"food-item": ["notebook", "pen"], "number": [1, 2]},
            "outputContexts": [{"name": context_name}]
        }
    }
    add_resp = client.post("/", json=add_payload)
    assert add_resp.status_code == 200
    assert "notebook" in add_resp.json()["fulfillmentText"].lower()

    # 2. Complete order
    complete_payload = {
        "queryResult": {
            "intent": {"displayName": "order.complete - context: ongoing-order"},
            "parameters": {},
            "outputContexts": [{"name": context_name}]
        }
    }
    complete_resp = client.post("/", json=complete_payload)
    assert complete_resp.status_code == 200
    assert "placed your order" in complete_resp.json()["fulfillmentText"].lower()

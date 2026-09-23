import pytest
import db_helper


SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1",
    "' OR 1=1 --",
    "admin' --",
    "admin' /*",
    "' UNION SELECT id, email, password_hash, 'admin', 1, datetime('now') FROM users --",
    "1; DROP TABLE orders; --",
    "1; DROP TABLE users; --",
    "' OR SLEEP(5) --",
    "'; EXEC xp_cmdshell('dir'); --",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password_hash FROM users LIMIT 1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
    "1' AND 1=0 UNION ALL SELECT 'admin', 'pass', 'hash' --",
    "' OR ''='",
    "\" OR \"\"=\"",
    "0 OR 1=1"
]


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sql_injection_get_user_by_email(payload, sample_user):
    """
    Attempts SQL injection on user lookup.
    Parameterized queries must treat the payload as a literal string.
    Must never return another user's account.
    """
    result = db_helper.get_user_by_email(payload)
    # The payload is not the sample user's email, so it must return None
    assert result is None, f"SQL Injection succeeded with payload: {payload}"


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sql_injection_get_order_status(payload):
    """
    Attempts SQL injection on order status lookup.
    Must handle gracefully without executing unauthorized SQL or crashing.
    """
    # Test with string payload directly
    status = db_helper.get_order_status(payload)
    assert status is None or isinstance(status, str)


def test_sql_injection_stacked_query_does_not_drop_tables(sample_user):
    """
    Penetration test: verifies that stacked DROP TABLE statements fail to drop tables.
    """
    malicious_query = "1; DROP TABLE users; --"
    db_helper.get_order_status(malicious_query)

    # Verify that users table is still intact and sample_user still exists!
    user = db_helper.get_user_by_email(sample_user["email"])
    assert user is not None, "CRITICAL: Table was dropped or corrupted by SQL Injection!"
    assert user["id"] == sample_user["user_id"]


def test_sql_injection_api_order_track(client):
    """
    Tests order tracking endpoint with SQL injection strings.
    Endpoint enforces positive integer, rejecting string payloads with 422.
    """
    for payload in ["' OR 1=1 --", "1; DROP TABLE orders; --"]:
        resp = client.post("/api/orders/track", json={"order_id": payload})
        assert resp.status_code == 422, "API should validate order_id as integer and reject string payloads"


def test_sql_injection_api_login(client, sample_user):
    """
    Attempts classic authentication bypass: email = ' OR '1'='1
    Must return 401 Unauthorized or 422 (never bypass authentication).
    """
    resp = client.post("/api/auth/login", json={
        "email": "alice@example.com' OR '1'='1",
        "password": "Password123!"
    })
    # Either rejected by Pydantic EmailStr (422) or authentication failure (401)
    assert resp.status_code in (401, 422), f"Expected 401 or 422, got {resp.status_code}"
    # Ensure tokens were NOT returned
    assert "access_token" not in resp.json()

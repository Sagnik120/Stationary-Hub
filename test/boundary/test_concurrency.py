import concurrent.futures
import pytest
from rate_limiter import limiter


def test_concurrent_registration_race_condition(client):
    """
    Spawns 5 concurrent threads attempting to register the exact same email address
    at the exact same microsecond.
    Verifies that database constraints ensure EXACTLY ONE registration succeeds (201),
    and all others are safely rejected with 409 Conflict (or 429 rate limit).
    """
    # Temporarily reset limiter to test DB race condition
    limiter.reset()

    target_email = "race_condition_test@example.com"
    payload = {
        "name": "Race User",
        "email": target_email,
        "password": "Password123!"
    }

    results = []

    def attempt_register():
        return client.post("/api/auth/register", json=payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(attempt_register) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    status_codes = [r.status_code for r in results]

    # Exactly one request must succeed with 201
    assert status_codes.count(201) == 1, f"Expected exactly one 201, got: {status_codes}"
    # All others must be 409 Conflict or 429 Rate limited
    for code in status_codes:
        assert code in (201, 409, 429), f"Unexpected status code under concurrency: {code}"

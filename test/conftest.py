import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import config
import db_helper
import security
from rate_limiter import limiter
from main import app
from starlette.testclient import TestClient


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    """
    Sets up a clean isolated database for every test session/function.
    Resets the rate limiter state.
    """
    test_db = tmp_path / "test_hub.db"
    db_helper.SQLITE_PATH = test_db
    db_helper.init_db(str(test_db))
    limiter.reset()
    yield test_db


@pytest.fixture
def client():
    """Returns a FastAPI TestClient configured with security middlewares."""
    return TestClient(app, base_url="http://testserver")


@pytest.fixture
def sample_user():
    """Creates a sample test user in the test database and returns credentials."""
    password = "TestUserPassword123!"
    pw_hash = security.hash_password(password)
    user_id = db_helper.create_user("Alice Wonderland", "alice@example.com", pw_hash, role="customer")
    return {
        "user_id": user_id,
        "name": "Alice Wonderland",
        "email": "alice@example.com",
        "password": password,
        "role": "customer"
    }


@pytest.fixture
def admin_user():
    """Creates a sample admin user in the test database and returns credentials."""
    password = "AdminPassword2026!#"
    pw_hash = security.hash_password(password)
    user_id = db_helper.create_user("Admin Root", "admin@stationaryhub.com", pw_hash, role="admin")
    return {
        "user_id": user_id,
        "name": "Admin Root",
        "email": "admin@stationaryhub.com",
        "password": password,
        "role": "admin"
    }

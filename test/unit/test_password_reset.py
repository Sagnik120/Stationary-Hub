import pytest
import hashlib
from datetime import datetime, timezone, timedelta
import security
import db_helper


def test_generate_reset_token_structure():
    """Verifies that generated reset tokens are URL-safe, high-entropy, and produce valid SHA-256 hashes."""
    raw_token, token_hash = security.generate_reset_token()
    assert isinstance(raw_token, str)
    assert len(raw_token) >= 32
    assert isinstance(token_hash, str)
    assert len(token_hash) == 64
    # Verify hash matches sha256
    expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert token_hash == expected_hash


def test_hash_token_deterministic():
    """Verifies that hashing a token is deterministic and whitespace-trimmed."""
    token = "test_reset_token_abc_123"
    hash1 = security.hash_token(token)
    hash2 = security.hash_token(f"  {token}  ")
    assert hash1 == hash2
    assert len(hash1) == 64


def test_token_uniqueness():
    """Verifies that successive token generations produce distinct random tokens."""
    tokens = {security.generate_reset_token()[0] for _ in range(50)}
    assert len(tokens) == 50

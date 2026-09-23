import pytest
from datetime import timedelta
from fastapi import HTTPException

import security
import config


def test_create_and_decode_access_token():
    user_payload = {"sub": "42", "email": "test@domain.com", "role": "customer", "name": "Bob"}
    token = security.create_access_token(user_payload)
    assert isinstance(token, str)

    decoded = security.decode_token(token, is_refresh=False)
    assert decoded["sub"] == "42"
    assert decoded["email"] == "test@domain.com"
    assert decoded["role"] == "customer"
    assert decoded["token_type"] == "access"
    assert "jti" in decoded
    assert "exp" in decoded
    assert "iat" in decoded


def test_create_and_decode_refresh_token():
    user_payload = {"sub": "42", "email": "test@domain.com"}
    token = security.create_refresh_token(user_payload)
    assert isinstance(token, str)

    decoded = security.decode_token(token, is_refresh=True)
    assert decoded["sub"] == "42"
    assert decoded["token_type"] == "refresh"
    assert "jti" in decoded


def test_reject_token_type_mismatch():
    # Pass access token to refresh decoder
    access_token = security.create_access_token({"sub": "42"})
    with pytest.raises(HTTPException) as exc_info:
        security.decode_token(access_token, is_refresh=True)
    assert exc_info.value.status_code == 401

    # Pass refresh token to access decoder
    refresh_token = security.create_refresh_token({"sub": "42"})
    with pytest.raises(HTTPException) as exc_info:
        security.decode_token(refresh_token, is_refresh=False)
    assert exc_info.value.status_code == 401


def test_token_expiration():
    # Create token expired 1 minute ago
    expired_delta = timedelta(minutes=-1)
    expired_token = security.create_access_token({"sub": "100"}, expires_delta=expired_delta)
    with pytest.raises(HTTPException) as exc_info:
        security.decode_token(expired_token, is_refresh=False)
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_tampered_token_signature():
    token = security.create_access_token({"sub": "100"})
    header, payload, signature = token.split(".")
    # Tamper with signature
    tampered_signature = signature[:-4] + "abcd"
    tampered_token = f"{header}.{payload}.{tampered_signature}"

    with pytest.raises(HTTPException) as exc_info:
        security.decode_token(tampered_token, is_refresh=False)
    assert exc_info.value.status_code == 401
    assert "tampered" in exc_info.value.detail.lower() or "invalid" in exc_info.value.detail.lower()

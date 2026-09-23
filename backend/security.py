import os
import re
import hmac
import hashlib
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import config

security_scheme = HTTPBearer(auto_error=False)

# Thread-safe in-memory cache for OAuth CSRF states: {state: (provider, expiry_timestamp)}
_oauth_states: Dict[str, tuple[str, float]] = {}
_oauth_lock = threading.Lock()


# ==========================================
# Password Hashing & Verification (PBKDF2)
# ==========================================

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with a unique random salt."""
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(config.SALT_LENGTH)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        config.PBKDF2_ITERATIONS
    )
    salt_hex = salt.hex()
    key_hex = key.hex()
    return f"pbkdf2:sha256:{config.PBKDF2_ITERATIONS}${salt_hex}${key_hex}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against stored hash using constant-time comparison."""
    if not plain_password or not hashed_password:
        return False
    try:
        parts = hashed_password.split('$')
        if len(parts) != 3:
            return False
        algo_part, salt_hex, expected_key_hex = parts
        _, _, iterations_str = algo_part.split(':')
        iterations = int(iterations_str)

        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(expected_key_hex)

        actual_key = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt,
            iterations
        )
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforces production password complexity rules:
    - Minimum 8 characters
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one digit [0-9]
    - At least one special symbol [!@#$%^&*(),.?":{}|<>]
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numeric digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_+=~`\[\]]', password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_email(email: str) -> bool:
    """Validates email format using RFC-compliant validation."""
    if not email or not isinstance(email, str) or len(email) > 254:
        return False
    if ".." in email or email.startswith(".") or email.endswith("."):
        return False
    try:
        from email_validator import validate_email as _check_email, EmailNotValidError
        _check_email(email, check_deliverability=False)
        return True
    except (EmailNotValidError, Exception):
        return False


# ==========================================
# JWT Access & Refresh Token Management
# ==========================================

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a short-lived cryptographically signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": secrets.token_hex(16),
        "token_type": "access"
    })
    encoded_jwt = jwt.encode(to_encode, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a long-lived cryptographically signed JWT refresh token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": secrets.token_hex(16),
        "token_type": "refresh"
    })
    encoded_jwt = jwt.encode(to_encode, config.JWT_REFRESH_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    return encoded_jwt


def decode_token(token: str, is_refresh: bool = False) -> Dict[str, Any]:
    """
    Decodes and rigorously validates a JWT token.
    Enforces valid signature, HS256 algorithm (blocks 'none' attack), and token_type.
    """
    secret = config.JWT_REFRESH_SECRET_KEY if is_refresh else config.JWT_SECRET_KEY
    expected_type = "refresh" if is_refresh else "access"
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[config.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "jti", "sub"]}
        )
        if payload.get("token_type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type: expected '{expected_type}'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAlgorithmError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token algorithm",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or tampered token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)) -> Dict[str, Any]:
    """
    FastAPI dependency that extracts and validates the JWT Bearer access token.
    Returns user payload or raises HTTP 401.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_token(token, is_refresh=False)
    return {
        "user_id": int(payload["sub"]),
        "email": payload.get("email"),
        "role": payload.get("role", "customer"),
        "name": payload.get("name", "")
    }


def require_admin(current_user: Dict[str, Any] = Security(get_current_user)) -> Dict[str, Any]:
    """Dependency restricting endpoint to administrators."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# ==========================================
# Password Reset Token Helpers
# ==========================================

def generate_reset_token() -> tuple[str, str]:
    """
    Generates a cryptographically secure 32-byte URL-safe reset token,
    and returns both the raw token (sent to user) and its SHA-256 hash (stored in DB).
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash


def hash_token(token: str) -> str:
    """Computes SHA-256 hash of a raw token."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


# ==========================================
# OAuth CSRF State Helpers
# ==========================================

def generate_oauth_state(provider: str, ttl_seconds: int = 300) -> str:
    """
    Generates a secure state token for OAuth CSRF protection.
    Stores the state in the in-memory registry with a TTL (default 5 minutes).
    """
    state = secrets.token_urlsafe(16)
    expiry = time.time() + ttl_seconds
    with _oauth_lock:
        # Cleanup expired states
        now = time.time()
        expired = [s for s, (_, exp) in _oauth_states.items() if exp < now]
        for s in expired:
            _oauth_states.pop(s, None)
        _oauth_states[state] = (provider.lower(), expiry)
    return state


def verify_and_consume_oauth_state(state: str, provider: str) -> bool:
    """
    Verifies that the OAuth state is valid, matches the provider,
    and has not expired. Consumes the state upon verification (single-use).
    """
    if not state:
        return False
    with _oauth_lock:
        entry = _oauth_states.pop(state, None)
        if not entry:
            return False
        stored_provider, expiry = entry
        if time.time() > expiry:
            return False
        return stored_provider == provider.lower()


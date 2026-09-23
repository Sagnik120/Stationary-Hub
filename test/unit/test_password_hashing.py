import pytest
import security


def test_hash_password_structure():
    password = "SecurePassword123!"
    hashed = security.hash_password(password)
    assert hashed.startswith("pbkdf2:sha256:310000$")
    parts = hashed.split("$")
    assert len(parts) == 3
    # Salt length hex (16 bytes = 32 hex chars)
    assert len(parts[1]) == 32
    # SHA-256 key hex (32 bytes = 64 hex chars)
    assert len(parts[2]) == 64


def test_hash_unique_salt():
    password = "SamePasswordTwice1!"
    hash1 = security.hash_password(password)
    hash2 = security.hash_password(password)
    assert hash1 != hash2, "Hashing same password twice must yield different salts and hashes"


def test_verify_password_success():
    password = "MyComplexPassword2026$#"
    hashed = security.hash_password(password)
    assert security.verify_password(password, hashed) is True


def test_verify_password_failure():
    password = "MyComplexPassword2026$#"
    hashed = security.hash_password(password)
    assert security.verify_password("WrongPassword!", hashed) is False
    assert security.verify_password("mycomplexpassword2026$#", hashed) is False  # case sensitive
    assert security.verify_password("", hashed) is False


def test_verify_tampered_hash():
    password = "ValidPassword123!"
    hashed = security.hash_password(password)
    # Tamper with hash bytes
    tampered = hashed[:-4] + "ffff"
    assert security.verify_password(password, tampered) is False
    # Malformed hash string
    assert security.verify_password(password, "malformed$hash$string") is False
    assert security.verify_password(password, "randomjunk") is False


def test_empty_password_raises_error():
    with pytest.raises(ValueError, match="Password cannot be empty"):
        security.hash_password("")

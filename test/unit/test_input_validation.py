import pytest
import security
import db_helper


@pytest.mark.parametrize("valid_password", [
    "Password123!",
    "SuperSecure#2026",
    "Admin_Key_99$",
    "P@ssw0rd!LongerVersion",
    "Complex!1234aB"
])
def test_valid_passwords_pass(valid_password):
    valid, msg = security.validate_password_strength(valid_password)
    assert valid is True
    assert msg == ""


@pytest.mark.parametrize("invalid_password,expected_error", [
    ("Short1!", "at least 8 characters"),
    ("alllowercasenouppercase1!", "at least one uppercase"),
    ("ALLUPPERCASENOLOWERCASE1!", "at least one lowercase"),
    ("NoDigitsInPassword!", "at least one numeric digit"),
    ("NoSpecialSymbols123", "at least one special character"),
    ("", "at least 8 characters")
])
def test_invalid_passwords_fail(invalid_password, expected_error):
    valid, msg = security.validate_password_strength(invalid_password)
    assert valid is False
    assert expected_error in msg


@pytest.mark.parametrize("valid_email", [
    "user@example.com",
    "john.doe@company.co.uk",
    "student_123@college.edu",
    "first+last@sub.domain.org"
])
def test_valid_emails_pass(valid_email):
    assert security.validate_email(valid_email) is True


@pytest.mark.parametrize("invalid_email", [
    "plainaddress",
    "@missingusername.com",
    "username@.com",
    "username@com",
    "username@domain..com",
    "",
    "   ",
    "a" * 260 + "@example.com"
])
def test_invalid_emails_fail(invalid_email):
    assert security.validate_email(invalid_email) is False


def test_stationery_catalog_pricing():
    assert db_helper.STATIONERY_PRICES["pen"] == 5.0
    assert db_helper.STATIONERY_PRICES["notebook"] == 80.0
    assert db_helper.STATIONERY_PRICES["ruler"] == 20.0
    assert db_helper.STATIONERY_PRICES["stapler"] == 50.0

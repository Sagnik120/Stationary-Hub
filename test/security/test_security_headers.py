import pytest


def test_security_headers_present_on_api_responses(client):
    """
    Verifies that all OWASP recommended security headers are present on API responses.
    """
    resp = client.get("/api/health")
    assert resp.status_code == 200

    # 1. MIME-sniffing
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    # 2. Clickjacking protection
    assert resp.headers.get("X-Frame-Options") == "DENY"

    # 3. Cross-Site Scripting (XSS)
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"

    # 4. HSTS
    hsts = resp.headers.get("Strict-Transport-Security")
    assert hsts is not None
    assert "max-age=" in hsts

    # 5. Content Security Policy
    csp = resp.headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp

    # 6. Referrer Policy
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_cors_preflight_headers(client):
    """Verifies CORS preflight handling for authorized frontend origins."""
    headers = {
        "Origin": "http://localhost:8080",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type,Authorization"
    }
    resp = client.options("/api/auth/login", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:8080"
    assert "POST" in resp.headers.get("access-control-allow-methods", "")

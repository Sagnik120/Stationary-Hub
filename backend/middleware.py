from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Appends OWASP recommended security headers and rate-limit metadata
    to every outgoing HTTP response.
    """
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # 1. Prevent MIME-sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Cross-Site Scripting (XSS) filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 4. Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # 5. Content Security Policy (CSP)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "media-src 'self'; "
            "connect-src 'self' http://localhost:8000 http://localhost:8080 http://127.0.0.1:8000 http://127.0.0.1:8080;"
        )

        # 6. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 7. Permissions Policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Attach rate-limit headers if present on request state
        if hasattr(request.state, "rate_limit_headers"):
            for header, value in request.state.rate_limit_headers.items():
                response.headers[header] = value

        return response

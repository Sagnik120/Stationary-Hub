import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Security & JWT Configurations
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "stationary_hub_jwt_super_secure_production_secret_key_2026_!@#$%^")
JWT_REFRESH_SECRET_KEY = os.getenv("JWT_REFRESH_SECRET_KEY", "stationary_hub_jwt_refresh_super_secure_key_2026_&*()_+~")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Database Configurations
# Supports 'mysql' or 'sqlite'
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").lower()
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
DB_NAME = os.getenv("DB_NAME", "stationary_hub")
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", str(BASE_DIR / "data" / "stationary_hub.db"))

# Rate Limiting Configurations (requests per window)
RATE_LIMIT_LOGIN_MAX = int(os.getenv("RATE_LIMIT_LOGIN_MAX", "5"))         # max 5 attempts per window
RATE_LIMIT_LOGIN_WINDOW = int(os.getenv("RATE_LIMIT_LOGIN_WINDOW", "60"))   # 60 seconds
RATE_LIMIT_REGISTER_MAX = int(os.getenv("RATE_LIMIT_REGISTER_MAX", "3"))   # max 3 per window
RATE_LIMIT_REGISTER_WINDOW = int(os.getenv("RATE_LIMIT_REGISTER_WINDOW", "60"))
RATE_LIMIT_DEFAULT_MAX = int(os.getenv("RATE_LIMIT_DEFAULT_MAX", "60"))     # max 60 per minute
RATE_LIMIT_DEFAULT_WINDOW = int(os.getenv("RATE_LIMIT_DEFAULT_WINDOW", "60"))

# Password Hashing Constants
PBKDF2_ITERATIONS = 310000  # OWASP recommendation
SALT_LENGTH = 16

# Password Reset Constants
PASSWORD_RESET_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "15"))
RATE_LIMIT_FORGOT_PW_MAX = int(os.getenv("RATE_LIMIT_FORGOT_PW_MAX", "3"))
RATE_LIMIT_FORGOT_PW_WINDOW = int(os.getenv("RATE_LIMIT_FORGOT_PW_WINDOW", "60"))

# OAuth / Social Login Configurations
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
FACEBOOK_CLIENT_ID = os.getenv("FACEBOOK_CLIENT_ID", "")
FACEBOOK_CLIENT_SECRET = os.getenv("FACEBOOK_CLIENT_SECRET", "")
OAUTH_REDIRECT_BASE = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8080/login.html")

# CORS Allowed Origins
CORS_ORIGINS = [
    origin.strip() for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080,http://localhost:3000,http://127.0.0.1:3000"
    ).split(",") if origin.strip()
]

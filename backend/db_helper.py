import os
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

import config

# Directory for SQLite fallback / development data
DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_PATH = Path(config.SQLITE_DB_PATH)

# Stationary standard price directory (per unit)
STATIONERY_PRICES = {
    "pen": 5.0,
    "pencil": 5.0,
    "notebook": 80.0,
    "eraser": 5.0,
    "ruler": 20.0,
    "marker": 15.0,
    "sharpener": 5.0,
    "stapler": 50.0,
    "highlighter": 35.0
}

# Global flag to track active engine
_ACTIVE_ENGINE = "sqlite"
_mysql_pool = None


def _init_mysql_pool():
    global _mysql_pool, _ACTIVE_ENGINE
    if config.DB_ENGINE == "mysql":
        try:
            import mysql.connector.pooling
            _mysql_pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="stationary_hub_pool",
                pool_size=5,
                pool_reset_session=True,
                host=config.DB_HOST,
                port=config.DB_PORT,
                user=config.DB_USER,
                password=config.DB_PASSWORD,
                database=config.DB_NAME
            )
            _ACTIVE_ENGINE = "mysql"
            print("Connected to MySQL production database pool.")
            return True
        except Exception as e:
            print(f"Notice: MySQL not available ({e}). Falling back to local secure SQLite engine.")
            _ACTIVE_ENGINE = "sqlite"
            return False
    else:
        _ACTIVE_ENGINE = "sqlite"
        return False


def get_db_connection():
    """
    Returns an active database connection.
    Supports MySQL pool if available, otherwise returns thread-safe SQLite connection.
    """
    global _mysql_pool, _ACTIVE_ENGINE
    if _ACTIVE_ENGINE == "mysql" and _mysql_pool:
        try:
            return _mysql_pool.get_connection()
        except Exception:
            pass
    # SQLite connection
    conn = sqlite3.connect(str(SQLITE_PATH), timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(custom_path: Optional[str] = None):
    """
    Initializes production schema tables with constraints, indexes,
    and foreign keys. Parameterized and safe.
    """
    target_path = Path(custom_path) if custom_path else SQLITE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target_path), timeout=30.0)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        pass

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Refresh Tokens Table (with rotation & replay protection)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 3. Orders Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        item_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        total_price REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Order Tracking Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS order_tracking (
        order_id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Indexes for fast lookup
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON refresh_tokens(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON refresh_tokens(token_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_order_id ON orders(order_id);")

    conn.commit()
    conn.close()


# Initialize database schema on module load
_init_mysql_pool()
init_db()


# ==========================================
# User Account Queries (Parameterized)
# ==========================================

def create_user(name: str, email: str, password_hash: str, role: str = "customer") -> Optional[int]:
    """Creates a new user record using strict parameterized SQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"
        cursor.execute(query, (name.strip(), email.strip().lower(), password_hash, role))
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        # Email already exists
        return None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by email using parameterized query."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, name, email, password_hash, role, is_active, created_at FROM users WHERE email = ? LIMIT 1"
        cursor.execute(query, (email.strip().lower(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        cursor.close()
        conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a user by ID using parameterized query."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, name, email, role, is_active, created_at FROM users WHERE id = ? LIMIT 1"
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        cursor.close()
        conn.close()


# ==========================================
# Refresh Token Queries (Parameterized)
# ==========================================

def store_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> bool:
    """Stores a cryptographically hashed refresh token."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, is_revoked) VALUES (?, ?, ?, 0)"
        cursor.execute(query, (user_id, token_hash, expires_at.isoformat()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error storing refresh token: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def is_refresh_token_valid(user_id: int, token_hash: str) -> bool:
    """Verifies that a refresh token exists, matches user, and has not been revoked or expired."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, expires_at, is_revoked FROM refresh_tokens WHERE user_id = ? AND token_hash = ? LIMIT 1"
        cursor.execute(query, (user_id, token_hash))
        row = cursor.fetchone()
        if not row:
            return False
        if row["is_revoked"] == 1:
            return False
        # Expiry check
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires_at.replace(tzinfo=timezone.utc):
            return False
        return True
    finally:
        cursor.close()
        conn.close()


def revoke_refresh_token(token_hash: str) -> bool:
    """Revokes a specific refresh token (used on token rotation and logout)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "UPDATE refresh_tokens SET is_revoked = 1 WHERE token_hash = ?"
        cursor.execute(query, (token_hash,))
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()


def revoke_all_user_tokens(user_id: int) -> bool:
    """Revokes all refresh tokens for a user (triggered if token theft/reuse is detected)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?"
        cursor.execute(query, (user_id,))
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()


# ==========================================
# Order & Stationery Queries (100% Parameterized)
# ==========================================

def insert_order_item(item_name: str, quantity: int, order_id: int) -> int:
    """
    Inserts an order item using parameterized SQL.
    Calculates unit price and total price automatically from verified catalog.
    """
    clean_item = item_name.strip().lower()
    unit_price = STATIONERY_PRICES.get(clean_item, 10.0)
    total_price = unit_price * quantity

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT INTO orders (order_id, item_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?)"
        cursor.execute(query, (order_id, clean_item, quantity, unit_price, total_price))
        conn.commit()
        return 1
    except Exception as e:
        print(f"Error inserting order item: {e}")
        conn.rollback()
        return -1
    finally:
        cursor.close()
        conn.close()


def insert_order_tracking(order_id: int, status: str) -> int:
    """Inserts or updates order tracking status using parameterized SQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT OR REPLACE INTO order_tracking (order_id, status, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
        cursor.execute(query, (order_id, status.strip()))
        conn.commit()
        return 1
    except Exception as e:
        print(f"Error inserting order tracking: {e}")
        conn.rollback()
        return -1
    finally:
        cursor.close()
        conn.close()


def get_total_order_price(order_id: int) -> float:
    """
    Calculates total price for an order ID using parameterized query.
    100% immune to SQL injection.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT COALESCE(SUM(total_price), 0.0) AS total FROM orders WHERE order_id = ?"
        cursor.execute(query, (order_id,))
        row = cursor.fetchone()
        return float(row["total"]) if row else 0.0
    finally:
        cursor.close()
        conn.close()


def get_next_order_id() -> int:
    """Calculates next order ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT MAX(order_id) AS max_id FROM orders"
        cursor.execute(query)
        row = cursor.fetchone()
        if row and row["max_id"] is not None:
            return int(row["max_id"]) + 1
        return 1
    finally:
        cursor.close()
        conn.close()


def get_order_status(order_id: int) -> Optional[str]:
    """
    Fetches the status of an order using strict parameterized SQL.
    100% immune to SQL injection.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT status FROM order_tracking WHERE order_id = ? LIMIT 1"
        cursor.execute(query, (order_id,))
        row = cursor.fetchone()
        if row:
            return row["status"]
        return None
    finally:
        cursor.close()
        conn.close()

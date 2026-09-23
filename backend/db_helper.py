import os
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta

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
        phone TEXT,
        address TEXT,
        avatar_url TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Safe column additions if table already existed
    for col, col_type in [("phone", "TEXT"), ("address", "TEXT"), ("avatar_url", "TEXT"), ("updated_at", "TIMESTAMP")]:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type};")
        except Exception:
            pass

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

    # 3. Password Resets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        is_used INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 4. OAuth Accounts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE (provider, provider_user_id)
    );
    """)

    # 5. Orders Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        user_id INTEGER,
        item_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        total_price REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'In Progress',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    for col, col_type in [("user_id", "INTEGER"), ("status", "TEXT DEFAULT 'In Progress'")]:
        try:
            cursor.execute(f"ALTER TABLE orders ADD COLUMN {col} {col_type};")
        except Exception:
            pass

    # 6. Order Tracking Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS order_tracking (
        order_id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 7. Indexes for fast lookup
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON refresh_tokens(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON refresh_tokens(token_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pw_reset_hash ON password_resets(token_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pw_reset_user ON password_resets(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_accounts(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_order_id ON orders(order_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);")

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
        query = "SELECT id, name, email, role, phone, address, avatar_url, is_active, created_at, updated_at FROM users WHERE id = ? LIMIT 1"
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        cursor.close()
        conn.close()


def update_user_profile(user_id: int, name: str, phone: Optional[str] = None, address: Optional[str] = None) -> bool:
    """Updates a user's personal profile information."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "UPDATE users SET name = ?, phone = ?, address = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        cursor.execute(query, (name.strip(), phone.strip() if phone else None, address.strip() if address else None, user_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def update_user_password(user_id: int, new_password_hash: str) -> bool:
    """Updates a user's password hash and revokes old sessions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        cursor.execute(query, (new_password_hash, user_id))
        cursor.execute("UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
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
# Password Reset Queries (Parameterized)
# ==========================================

def create_password_reset(user_id: int, token_hash: str, expires_in_minutes: int = 15) -> bool:
    """
    Creates a password reset request.
    Invalidates any existing unused tokens for this user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Invalidate old unused tokens
        cursor.execute("UPDATE password_resets SET is_used = 1 WHERE user_id = ?", (user_id,))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
        query = "INSERT INTO password_resets (user_id, token_hash, expires_at, is_used) VALUES (?, ?, ?, 0)"
        cursor.execute(query, (user_id, token_hash, expires_at.isoformat()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating password reset: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def verify_password_reset_token(token_hash: str) -> Optional[Dict[str, Any]]:
    """
    Verifies that a reset token exists, is unused, and has not expired.
    Returns associated user details if valid.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
        SELECT pr.id AS reset_id, pr.user_id, pr.expires_at, pr.is_used, u.email, u.name
        FROM password_resets pr
        JOIN users u ON pr.user_id = u.id
        WHERE pr.token_hash = ? AND pr.is_used = 0
        LIMIT 1
        """
        cursor.execute(query, (token_hash,))
        row = cursor.fetchone()
        if not row:
            return None
        expires_at = datetime.fromisoformat(row["expires_at"]).replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return None
        return dict(row)
    finally:
        cursor.close()
        conn.close()


def complete_password_reset(token_hash: str, new_password_hash: str) -> bool:
    """
    Applies the new password hash, marks the reset token used,
    and revokes all existing refresh tokens for the user.
    """
    record = verify_password_reset_token(token_hash)
    if not record:
        return False
    user_id = record["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_password_hash, user_id))
        cursor.execute("UPDATE password_resets SET is_used = 1 WHERE token_hash = ?", (token_hash,))
        cursor.execute("UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error completing password reset: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


# ==========================================
# OAuth Accounts Queries (Parameterized)
# ==========================================

def get_user_by_oauth(provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user linked to a third-party OAuth provider."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
        SELECT u.id, u.name, u.email, u.role, u.is_active, u.created_at
        FROM users u
        JOIN oauth_accounts oa ON u.id = oa.user_id
        WHERE oa.provider = ? AND oa.provider_user_id = ?
        LIMIT 1
        """
        cursor.execute(query, (provider.lower(), str(provider_user_id)))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        cursor.close()
        conn.close()


def link_oauth_account(user_id: int, provider: str, provider_user_id: str, email: str) -> bool:
    """Links a third-party OAuth account to an existing user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_user_id, email) VALUES (?, ?, ?, ?)"
        cursor.execute(query, (user_id, provider.lower(), str(provider_user_id), email.strip().lower()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error linking oauth account: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


# ==========================================
# Order & Stationery Queries (100% Parameterized)
# ==========================================

def insert_order_item(item_name: str, quantity: int, order_id: int, user_id: Optional[int] = None) -> int:
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
        query = "INSERT INTO orders (order_id, user_id, item_name, quantity, unit_price, total_price, status) VALUES (?, ?, ?, ?, ?, ?, 'In Progress')"
        cursor.execute(query, (order_id, user_id, clean_item, quantity, unit_price, total_price))
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


# ==========================================
# User Order History & Management (IDOR Protected)
# ==========================================

def get_user_orders(user_id: int) -> List[Dict[str, Any]]:
    """
    Retrieves all orders placed by a specific user with aggregated totals.
    Strictly scoped to user_id to prevent IDOR attacks.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
        SELECT 
            o.order_id,
            COALESCE(ot.status, o.status, 'In Progress') AS status,
            COUNT(o.id) AS item_count,
            COALESCE(SUM(o.total_price), 0.0) AS total_price,
            MIN(o.created_at) AS created_at
        FROM orders o
        LEFT JOIN order_tracking ot ON o.order_id = ot.order_id
        WHERE o.user_id = ?
        GROUP BY o.order_id
        ORDER BY o.order_id DESC
        """
        cursor.execute(query, (user_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        cursor.close()
        conn.close()


def get_order_details(order_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves full itemized details for an order.
    If user_id is provided, enforces that the order belongs to that user (IDOR prevention).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if user_id is not None:
            query = """
            SELECT o.id, o.order_id, o.user_id, o.item_name, o.quantity, o.unit_price, o.total_price,
                   COALESCE(ot.status, o.status, 'In Progress') AS status, o.created_at
            FROM orders o
            LEFT JOIN order_tracking ot ON o.order_id = ot.order_id
            WHERE o.order_id = ? AND o.user_id = ?
            """
            cursor.execute(query, (order_id, user_id))
        else:
            query = """
            SELECT o.id, o.order_id, o.user_id, o.item_name, o.quantity, o.unit_price, o.total_price,
                   COALESCE(ot.status, o.status, 'In Progress') AS status, o.created_at
            FROM orders o
            LEFT JOIN order_tracking ot ON o.order_id = ot.order_id
            WHERE o.order_id = ?
            """
            cursor.execute(query, (order_id,))
        rows = cursor.fetchall()
        if not rows:
            return None
        items = [
            {
                "item_name": r["item_name"],
                "quantity": r["quantity"],
                "unit_price": r["unit_price"],
                "total_price": r["total_price"]
            }
            for r in rows
        ]
        first = rows[0]
        return {
            "order_id": first["order_id"],
            "user_id": first["user_id"],
            "status": first["status"],
            "created_at": first["created_at"],
            "total_price": sum(item["total_price"] for item in items),
            "items": items
        }
    finally:
        cursor.close()
        conn.close()


def create_user_order(user_id: int, items: List[Dict[str, Any]]) -> int:
    """
    Creates a new multi-item order linked to a user.
    Calculates prices and initializes tracking status.
    """
    if not items:
        raise ValueError("Order must contain at least one item")

    order_id = get_next_order_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        for it in items:
            clean_item = it["item_name"].strip().lower()
            qty = int(it["quantity"])
            unit_price = STATIONERY_PRICES.get(clean_item, 10.0)
            total = unit_price * qty
            cursor.execute(
                "INSERT INTO orders (order_id, user_id, item_name, quantity, unit_price, total_price, status) VALUES (?, ?, ?, ?, ?, ?, 'In Progress')",
                (order_id, user_id, clean_item, qty, unit_price, total)
            )
        cursor.execute(
            "INSERT OR REPLACE INTO order_tracking (order_id, status, updated_at) VALUES (?, 'In Progress', CURRENT_TIMESTAMP)",
            (order_id,)
        )
        conn.commit()
        return order_id
    except Exception as e:
        print(f"Error creating user order: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def cancel_user_order(order_id: int, user_id: int) -> bool:
    """
    Cancels an order if it belongs to user_id and is in an eligible status.
    IDOR-safe.
    """
    order = get_order_details(order_id, user_id=user_id)
    if not order:
        return False
    current_status = order["status"].lower()
    if current_status in ("delivered", "cancelled"):
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE orders SET status = 'Cancelled' WHERE order_id = ? AND user_id = ?", (order_id, user_id))
        cursor.execute("UPDATE order_tracking SET status = 'Cancelled', updated_at = CURRENT_TIMESTAMP WHERE order_id = ?", (order_id,))
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()


def duplicate_user_order(order_id: int, user_id: int) -> Optional[int]:
    """
    Duplicates items from an existing order into a brand new order.
    IDOR-safe: only allows duplicating user's own orders.
    """
    order = get_order_details(order_id, user_id=user_id)
    if not order:
        return None
    items = [{"item_name": it["item_name"], "quantity": it["quantity"]} for it in order["items"]]
    return create_user_order(user_id, items)


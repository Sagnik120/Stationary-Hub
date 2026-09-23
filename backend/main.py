import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

import config
import db_helper
import generic_helper
from security import (
    hash_password,
    verify_password,
    validate_password_strength,
    validate_email,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user
)
from rate_limiter import apply_rate_limit, limiter
from middleware import SecurityHeadersMiddleware

app = FastAPI(
    title="Stationery Hub API",
    description="Production-grade secure API for Stationery Hub with JWT authentication, rate limiting, and SQL injection protection.",
    version="2.0.0"
)

# 1. Attach Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 2. Attach CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"]
)

# In-memory ongoing Dialogflow chatbot orders
inprogress_orders = {}


# ==========================================
# Pydantic Request & Response Schemas
# ==========================================

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full user name")
    email: EmailStr = Field(..., description="Valid user email address")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10, description="Valid JWT refresh token")


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: Optional[str] = None


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class OrderTrackRequest(BaseModel):
    order_id: int = Field(..., ge=1, description="Positive integer order ID")


# ==========================================
# Health Check Endpoint
# ==========================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_helper._ACTIVE_ENGINE
    }


# ==========================================
# Authentication Endpoints
# ==========================================

@app.post("/api/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(req: Request, data: RegisterRequest):
    """
    Registers a new user account with production password validation,
    PBKDF2-HMAC-SHA256 hashing, and automated token generation.
    Protected by rate limiting (3 requests / minute).
    """
    apply_rate_limit(req, "auth:register", config.RATE_LIMIT_REGISTER_MAX, config.RATE_LIMIT_REGISTER_WINDOW)

    # 1. Enforce password complexity
    valid_pw, pw_msg = validate_password_strength(data.password)
    if not valid_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_msg
        )

    # 2. Check if user already exists
    existing = db_helper.get_user_by_email(data.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists."
        )

    # 3. Hash password and insert user (parameterized)
    pw_hash = hash_password(data.password)
    user_id = db_helper.create_user(data.name, data.email, pw_hash, role="customer")
    if not user_id:
        if db_helper.get_user_by_email(data.email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email address already exists."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user account. Please try again."
        )

    # 4. Generate JWT tokens
    user_payload = {"sub": str(user_id), "email": data.email, "role": "customer", "name": data.name}
    access_token = create_access_token(user_payload)
    refresh_token = create_refresh_token(user_payload)

    # 5. Store hashed refresh token in database for rotation tracking
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    db_helper.store_refresh_token(user_id, refresh_hash, expires_at)

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user_id,
            name=data.name,
            email=data.email,
            role="customer"
        )
    )


@app.post("/api/auth/login", response_model=AuthResponse)
async def login(req: Request, data: LoginRequest):
    """
    Authenticates user credentials against PBKDF2 hash.
    Protected by rate limiting (5 requests / minute) to prevent brute-force attacks.
    """
    apply_rate_limit(req, "auth:login", config.RATE_LIMIT_LOGIN_MAX, config.RATE_LIMIT_LOGIN_WINDOW)

    user = db_helper.get_user_by_email(data.email)
    if not user:
        # Constant-time dummy verification to protect against user enumeration timing attacks
        verify_password("dummy_password", "pbkdf2:sha256:310000$0000000000000000$0000000000000000")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.get("is_active") == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Please contact customer support."
        )

    # Generate JWT tokens
    user_payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "name": user["name"]
    }
    access_token = create_access_token(user_payload)
    refresh_token = create_refresh_token(user_payload)

    # Store refresh token hash
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    db_helper.store_refresh_token(user["id"], refresh_hash, expires_at)

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            role=user["role"],
            created_at=str(user.get("created_at", ""))
        )
    )


@app.post("/api/auth/refresh")
async def refresh_tokens(req: Request, data: RefreshRequest):
    """
    Exchanges a valid refresh token for a brand-new access token and rotates the refresh token.
    Detects token replay attacks: if a revoked token is used, revokes all tokens for that user.
    """
    apply_rate_limit(req, "auth:refresh", 10, 60)

    payload = decode_token(data.refresh_token, is_refresh=True)
    user_id = int(payload["sub"])
    old_hash = hashlib.sha256(data.refresh_token.encode()).hexdigest()

    # Verify if refresh token is valid and unrevoked in database
    is_valid = db_helper.is_refresh_token_valid(user_id, old_hash)
    if not is_valid:
        # Possible token theft / replay attack: revoke all tokens for this user!
        db_helper.revoke_all_user_tokens(user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or has already been used. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Revoke old refresh token (single-use token rotation)
    db_helper.revoke_refresh_token(old_hash)

    # Fetch user data
    user = db_helper.get_user_by_id(user_id)
    if not user or user.get("is_active") == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer active"
        )

    # Generate new access token and new rotated refresh token
    user_payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "name": user["name"]
    }
    new_access_token = create_access_token(user_payload)
    new_refresh_token = create_refresh_token(user_payload)

    # Store new refresh token hash
    new_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    db_helper.store_refresh_token(user_id, new_hash, expires_at)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@app.post("/api/auth/logout")
async def logout(req: Request, data: RefreshRequest):
    """
    Revokes the provided refresh token in the database.
    """
    try:
        payload = decode_token(data.refresh_token, is_refresh=True)
        token_hash = hashlib.sha256(data.refresh_token.encode()).hexdigest()
        db_helper.revoke_refresh_token(token_hash)
    except Exception:
        # Always return success on logout to prevent enumeration
        pass
    return {"message": "Logged out successfully"}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Protected endpoint: returns the authenticated user's profile.
    Requires Authorization: Bearer <valid_access_token>.
    """
    user = db_helper.get_user_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        role=user["role"],
        created_at=str(user.get("created_at", ""))
    )


# ==========================================
# Secure Order Tracking API
# ==========================================

@app.post("/api/orders/track")
async def api_track_order(data: OrderTrackRequest):
    """
    Secure parameterized endpoint for tracking orders.
    Enforces positive integer order ID. Immune to SQL injection.
    """
    order_status = db_helper.get_order_status(data.order_id)
    if order_status:
        return {"order_id": data.order_id, "status": order_status}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No order found with ID {data.order_id}"
        )


# ==========================================
# Dialogflow Webhook Integration
# ==========================================

@app.post("/")
async def handle_request(request: Request):
    """
    Dialogflow chatbot webhook entrypoint with strict parameter sanitization.
    """
    try:
        payload = await request.json()
        intent = payload['queryResult']['intent']['displayName']
        parameters = payload['queryResult'].get('parameters', {})
        output_contexts = payload['queryResult'].get('outputContexts', [])
        session_id = generic_helper.extract_session_id(output_contexts[0]["name"]) if output_contexts else "default"

        intent_handler_dict = {
            'order.add - context: ongoing-order': add_to_order,
            'order.remove - context: ongoing-order': remove_from_order,
            'order.complete - context: ongoing-order': complete_order,
            'track.order - context: ongoing-tracking': track_order
        }

        if intent in intent_handler_dict:
            return intent_handler_dict[intent](parameters, session_id)
        else:
            return JSONResponse(content={"fulfillmentText": "I did not recognize that intent. How can I help you?"})
    except Exception as e:
        return JSONResponse(content={"fulfillmentText": f"An error occurred: {str(e)}"})


def save_to_db(order: dict):
    next_order_id = db_helper.get_next_order_id()
    for item_name, quantity in order.items():
        try:
            qty = max(1, int(quantity))
            rcode = db_helper.insert_order_item(item_name, qty, next_order_id)
            if rcode == -1:
                return -1
        except (ValueError, TypeError):
            return -1

    db_helper.insert_order_tracking(next_order_id, "in progress")
    return next_order_id


def complete_order(parameters: dict, session_id: str):
    if session_id not in inprogress_orders:
        fulfillment_text = "I'm having trouble finding your order. Can you place a new order please?"
    else:
        order = inprogress_orders[session_id]
        order_id = save_to_db(order)
        if order_id == -1:
            fulfillment_text = "Sorry, I couldn't process your order due to a backend error. Please try again."
        else:
            order_total = db_helper.get_total_order_price(order_id)
            fulfillment_text = (
                f"Awesome! We have placed your order. "
                f"Your order ID is #{order_id}. "
                f"Total amount is ₹{order_total:.2f} which you can pay upon delivery."
            )
        del inprogress_orders[session_id]

    return JSONResponse(content={"fulfillmentText": fulfillment_text})


def add_to_order(parameters: dict, session_id: str):
    items = parameters.get("food-item", [])
    quantities = parameters.get("number", [])

    if len(items) != len(quantities):
        fulfillment_text = "Sorry, I didn't understand. Can you please specify items and quantities clearly?"
    else:
        new_dict = dict(zip(items, quantities))
        if session_id in inprogress_orders:
            inprogress_orders[session_id].update(new_dict)
        else:
            inprogress_orders[session_id] = new_dict

        order_str = generic_helper.get_str_from_food_dict(inprogress_orders[session_id])
        fulfillment_text = f"So far you have: {order_str}. Do you need anything else?"

    return JSONResponse(content={"fulfillmentText": fulfillment_text})


def remove_from_order(parameters: dict, session_id: str):
    if session_id not in inprogress_orders:
        return JSONResponse(content={"fulfillmentText": "No active order found to remove items from."})

    items = parameters.get("food-item", [])
    current_order = inprogress_orders[session_id]
    removed_items = []
    not_found = []

    for item in items:
        if item in current_order:
            removed_items.append(item)
            del current_order[item]
        else:
            not_found.append(item)

    msg_parts = []
    if removed_items:
        msg_parts.append(f"Removed {', '.join(removed_items)} from your order.")
    if not_found:
        msg_parts.append(f"Could not find {', '.join(not_found)} in your order.")

    if not current_order:
        msg_parts.append("Your order is now empty.")
    else:
        order_str = generic_helper.get_str_from_food_dict(current_order)
        msg_parts.append(f"Remaining in your order: {order_str}")

    return JSONResponse(content={"fulfillmentText": " ".join(msg_parts)})


def track_order(parameters: dict, session_id: str):
    try:
        order_id = int(parameters['order_id'])
        order_status = db_helper.get_order_status(order_id)
        if order_status:
            fulfillment_text = f"The order status for order #{order_id} is: {order_status}"
        else:
            fulfillment_text = f"No order found with order ID #{order_id}."
    except (ValueError, KeyError, TypeError):
        fulfillment_text = "Please provide a valid numeric order ID."

    return JSONResponse(content={"fulfillmentText": fulfillment_text})
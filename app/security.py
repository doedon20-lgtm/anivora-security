"""
AniVora Security
================

Central security foundation for AniVora services.

Designed to be reused by:
    - AniVora Builder
    - AniVora API
    - AniVora Cloud
    - AniVora Compute
    - AniVora Cloud Phone
    - AniVora VPN
    
Security responsibilities:
    - Password hashing
    - JWT authentication
    - API-key hashing and comparison
    - Cryptographically secure token generation
    - Input validation
    - Security headers
    - CORS configuration
    - In-memory rate limiting
    - Sensitive-data redaction
    - Security event logging
    - Request ID generation
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from fastapi import HTTPException, Request, Response
from pwdlib import PasswordHash


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = os.getenv(
    "ANIVORA_SECURITY_APP_NAME",
    "AniVora Security"
)

VERSION = os.getenv(
    "ANIVORA_SECURITY_VERSION",
    "0.1.0"
)

SECRET_KEY = os.getenv(
    "ANIVORA_SECRET_KEY",
    ""
)

JWT_ALGORITHM = os.getenv(
    "ANIVORA_JWT_ALGORITHM",
    "HS256"
)

JWT_ISSUER = os.getenv(
    "ANIVORA_JWT_ISSUER",
    "anivora"
)

JWT_AUDIENCE = os.getenv(
    "ANIVORA_JWT_AUDIENCE",
    "anivora-api"
)

JWT_EXPIRE_MINUTES = int(
    os.getenv(
        "ANIVORA_JWT_EXPIRE_MINUTES",
        "30"
    )
)

RATE_LIMIT_REQUESTS = int(
    os.getenv(
        "ANIVORA_RATE_LIMIT_REQUESTS",
        "60"
    )
)

RATE_LIMIT_WINDOW_SECONDS = int(
    os.getenv(
        "ANIVORA_RATE_LIMIT_WINDOW_SECONDS",
        "60"
    )
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ANIVORA_ALLOWED_ORIGINS",
        "http://localhost:3000"
    ).split(",")
    if origin.strip()
]


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("anivora.security")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        )
    )


# ============================================================
# PASSWORD HASHING
# ============================================================

password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Securely hash a password.

    Passwords must NEVER be stored in plaintext.
    """

    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if len(password) < 8:
        raise ValueError(
            "Password must contain at least 8 characters."
        )

    if len(password) > 256:
        raise ValueError(
            "Password is too long."
        )

    return password_hasher.hash(password)


def verify_password(
    password: str,
    password_hash: str
) -> bool:
    """
    Verify a password against its stored hash.
    """

    if not password or not password_hash:
        return False

    try:
        return password_hasher.verify(
            password,
            password_hash
        )
    except Exception:
        return False


# ============================================================
# SECURE RANDOM VALUES
# ============================================================

def generate_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    """

    if length < 16:
        raise ValueError(
            "Token length must be at least 16."
        )

    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """
    Generate an AniVora API key.

    Example:
        av_xxxxxxxxxxxxxxxxx
    """

    return (
        "av_"
        + secrets.token_urlsafe(32)
    )


def generate_request_id() -> str:
    """
    Generate a unique request ID.
    """

    return (
        "req_"
        + secrets.token_hex(16)
    )


def generate_user_id() -> str:
    """
    Generate an AniVora user ID.
    """

    return (
        "usr_"
        + secrets.token_hex(16)
    )


# ============================================================
# API KEY SECURITY
# ============================================================

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key before storing it.

    The raw API key should not be stored in a database.
    """

    if not api_key:
        raise ValueError(
            "API key cannot be empty."
        )

    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def verify_api_key(
    api_key: str,
    stored_hash: str
) -> bool:
    """
    Constant-time API-key comparison.
    """

    if not api_key or not stored_hash:
        return False

    calculated_hash = hash_api_key(
        api_key
    )

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


# ============================================================
# JWT AUTHENTICATION
# ============================================================

def _require_secret_key() -> None:
    """
    Fail closed if the production secret is missing.
    """

    if not SECRET_KEY:
        raise RuntimeError(
            "ANIVORA_SECRET_KEY is not configured."
        )

    if len(SECRET_KEY) < 32:
        raise RuntimeError(
            "ANIVORA_SECRET_KEY must contain "
            "at least 32 characters."
        )


def create_access_token(
    subject: str,
    scopes: Optional[list[str]] = None,
    expires_minutes: Optional[int] = None
) -> str:
    """
    Create a short-lived JWT access token.
    """

    _require_secret_key()

    if not subject:
        raise ValueError(
            "Token subject cannot be empty."
        )

    if expires_minutes is None:
        expires_minutes = JWT_EXPIRE_MINUTES

    now = datetime.now(timezone.utc)

    expires_at = (
        now
        + timedelta(
            minutes=expires_minutes
        )
    )

    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "jti": secrets.token_hex(16),
        "scopes": scopes or []
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )


def decode_access_token(
    token: str
) -> dict[str, Any]:
    """
    Validate and decode a JWT access token.

    Invalid tokens fail closed.
    """

    _require_secret_key()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER
        )

        if not payload.get("sub"):
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token."
            )

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication token has expired."
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token."
        )


def get_bearer_token(
    request: Request
) -> str:
    """
    Extract a Bearer token from Authorization header.
    """

    authorization = request.headers.get(
        "Authorization",
        ""
    )

    if not authorization.startswith(
        "Bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token."
        )

    token = authorization[
        len("Bearer "):
    ].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token."
        )

    return token


def authenticate_request(
    request: Request
) -> dict[str, Any]:
    """
    Authenticate an incoming request using JWT.
    """

    token = get_bearer_token(request)

    return decode_access_token(
        token
    )


def require_scope(
    payload: dict[str, Any],
    required_scope: str
) -> None:
    """
    Enforce authorization scope.

    Authentication asks:
        Who are you?

    Authorization asks:
        Are you allowed to do this?
    """

    scopes = payload.get(
        "scopes",
        []
    )

    if required_scope not in scopes:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions."
        )


# ============================================================
# INPUT VALIDATION
# ============================================================

USERNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9_.-]{3,32}$"
)

API_NAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9_.-]{1,64}$"
)


def validate_username(
    username: str
) -> str:
    """
    Validate a username.
    """

    if not isinstance(
        username,
        str
    ):
        raise ValueError(
            "Username must be text."
        )

    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(
        username
    ):
        raise ValueError(
            "Username contains invalid characters."
        )

    return username


def validate_api_name(
    name: str
) -> str:
    """
    Validate project/API names.
    """

    if not isinstance(
        name,
        str
    ):
        raise ValueError(
            "Name must be text."
        )

    name = name.strip()

    if not API_NAME_PATTERN.fullmatch(
        name
    ):
        raise ValueError(
            "Name contains invalid characters."
        )

    return name


def validate_text(
    value: str,
    max_length: int = 10000
) -> str:
    """
    General server-side text validation.
    """

    if not isinstance(
        value,
        str
    ):
        raise ValueError(
            "Value must be text."
        )

    value = value.strip()

    if not value:
        raise ValueError(
            "Value cannot be empty."
        )

    if len(value) > max_length:
        raise ValueError(
            "Value exceeds maximum length."
        )

    return value


def validate_prompt(
    prompt: str,
    max_length: int = 20000
) -> str:
    """
    Validate an AI prompt.

    This does NOT mean the prompt is trusted.
    AI-generated output must still be sandboxed
    before execution.
    """

    return validate_text(
        prompt,
        max_length=max_length
    )


# ============================================================
# RATE LIMITING
# ============================================================

class RateLimiter:
    """
    Simple in-memory rate limiter.

    Good for development and a single process.

    Production deployment should use a shared
    store such as Redis or an edge/WAF limiter
    when multiple instances are running.
    """

    def __init__(
        self,
        max_requests: int = RATE_LIMIT_REQUESTS,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(
            deque
        )

    def _cleanup(
        self,
        key: str,
        now: float
    ) -> None:

        request_times = self.requests[key]

        cutoff = (
            now
            - self.window_seconds
        )

        while (
            request_times
            and request_times[0] <= cutoff
        ):
            request_times.popleft()

    def allow(
        self,
        key: str
    ) -> bool:

        now = time.monotonic()

        self._cleanup(
            key,
            now
        )

        request_times = self.requests[key]

        if len(request_times) >= self.max_requests:
            return False

        request_times.append(now)

        return True

    def remaining(
        self,
        key: str
    ) -> int:

        now = time.monotonic()

        self._cleanup(
            key,
            now
        )

        return max(
            0,
            self.max_requests
            - len(self.requests[key])
        )

    def reset(
        self,
        key: str
    ) -> None:

        self.requests.pop(
            key,
            None
        )


rate_limiter = RateLimiter()


def get_client_identifier(
    request: Request
) -> str:
    """
    Identify a request for rate limiting.

    Prefer an authenticated user ID when available.
    Otherwise use the direct client address.

    Do not blindly trust arbitrary X-Forwarded-For
    headers unless the deployment has a trusted proxy.
    """

    user_id = getattr(
        request.state,
        "user_id",
        None
    )

    if user_id:
        return f"user:{user_id}"

    if request.client:
        return (
            f"ip:{request.client.host}"
        )

    return "unknown"


def enforce_rate_limit(
    request: Request
) -> None:

    key = get_client_identifier(
        request
    )

    if not rate_limiter.allow(
        key
    ):
        logger.warning(
            "Rate limit exceeded: %s",
            key
        )

        raise HTTPException(
            status_code=429,
            detail="Too many requests. Try again later."
        )


# ============================================================
# SECURITY HEADERS
# ============================================================

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",

    "X-Frame-Options": "DENY",

    "Referrer-Policy": (
        "strict-origin-when-cross-origin"
    ),

    "Permissions-Policy": (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    ),

    "Content-Security-Policy": (
        "default-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
}


def add_security_headers(
    response: Response
) -> Response:
    """
    Add baseline HTTP security headers.

    HSTS should normally be enabled only when
    the service is permanently served through HTTPS.
    """

    for (
        header,
        value
    ) in SECURITY_HEADERS.items():

        response.headers[
            header
        ] = value

    return response


def add_hsts_header(
    response: Response
) -> Response:
    """
    Add HTTP Strict Transport Security.

    Only use this when the domain is HTTPS-only.
    """

    response.headers[
        "Strict-Transport-Security"
    ] = (
        "max-age=31536000; "
        "includeSubDomains"
    )

    return response


# ============================================================
# CORS
# ============================================================

def get_allowed_origins() -> list[str]:
    """
    Return explicitly configured CORS origins.

    Never use wildcard '*' together with
    credentialed browser requests.
    """

    return ALLOWED_ORIGINS.copy()


# ============================================================
# COOKIE SECURITY
# ============================================================

def secure_cookie_options() -> dict[str, Any]:
    """
    Recommended settings for authentication cookies.
    """

    return {
        "secure": True,
        "httponly": True,
        "samesite": "lax",
        "path": "/"
    }


# ============================================================
# SENSITIVE DATA REDACTION
# ============================================================

SENSITIVE_FIELDS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
    "secret_key",
    "private_key",
    "authorization",
    "cookie",
    "session",
    "credit_card",
    "card_number"
}


def redact_sensitive_data(
    data: Any
) -> Any:
    """
    Remove sensitive fields before logging.

    This prevents passwords, tokens and API keys
    from accidentally appearing in logs.
    """

    if isinstance(
        data,
        dict
    ):
        result = {}

        for key, value in data.items():

            normalized_key = str(
                key
            ).lower()

            if normalized_key in SENSITIVE_FIELDS:
                result[key] = "[REDACTED]"
            else:
                result[key] = (
                    redact_sensitive_data(
                        value
                    )
                )

        return result

    if isinstance(
        data,
        list
    ):
        return [
            redact_sensitive_data(
                item
            )
            for item in data
        ]

    if isinstance(
        data,
        tuple
    ):
        return tuple(
            redact_sensitive_data(
                item
            )
            for item in data
        )

    return data


# ============================================================
# SECURITY EVENT LOGGING
# ============================================================

def security_event(
    event: str,
    request: Optional[Request] = None,
    user_id: Optional[str] = None,
    success: bool = True,
    details: Optional[dict[str, Any]] = None
) -> None:
    """
    Record a security-relevant event.

    Never log passwords, API keys, bearer tokens,
    private keys or other sensitive credentials.
    """

    event_data = {
        "event": event,
        "success": success,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "user_id": user_id,
        "request_id": (
            getattr(
                request.state,
                "request_id",
                None
            )
            if request
            else None
        ),
        "client": (
            request.client.host
            if request and request.client
            else None
        ),
        "details": redact_sensitive_data(
            details or {}
        )
    }

    logger.info(
        "SECURITY_EVENT %s",
        event_data
    )


# ============================================================
# REQUEST SECURITY
# ============================================================

async def security_middleware(
    request: Request,
    call_next
):
    """
    Global security middleware.

    Adds:
        - Request ID
        - Security headers
        - Rate limiting
        - Basic request protection
    """

    request_id = generate_request_id()

    request.state.request_id = request_id

    try:
        enforce_rate_limit(
            request
        )

        response = await call_next(
            request
        )

        add_security_headers(
            response
        )

        response.headers[
            "X-Request-ID"
        ] = request_id

        return response

    except HTTPException:
        raise

    except Exception as error:

        security_event(
            event="unhandled_exception",
            request=request,
            success=False,
            details={
                "error_type": type(
                    error
                ).__name__
            }
        )

        raise


# ============================================================
# AUTHORIZATION HELPERS
# ============================================================

def require_authenticated_user(
    request: Request
) -> dict[str, Any]:

    payload = authenticate_request(
        request
    )

    request.state.user_id = payload[
        "sub"
    ]

    return payload


def require_user(
    request: Request,
    expected_user_id: str
) -> dict[str, Any]:
    """
    Enforce ownership.

    This prevents users from accessing
    another user's resources simply by changing
    an ID in a URL.
    """

    payload = (
        require_authenticated_user(
            request
        )
    )

    current_user = payload[
        "sub"
    ]

    if not hmac.compare_digest(
        current_user,
        expected_user_id
    ):
        security_event(
            event="authorization_denied",
            request=request,
            user_id=current_user,
            success=False,
            details={
                "reason": "resource ownership mismatch"
            }
        )

        raise HTTPException(
            status_code=403,
            detail="Access denied."
        )

    return payload


# ============================================================
# SAFE ERROR HANDLING
# ============================================================

def safe_error_message(
    error: Exception
) -> str:
    """
    Convert internal exceptions into safe public messages.

    Do not expose stack traces, database details,
    filesystem paths, credentials or internal
    infrastructure information to users.
    """

    logger.exception(
        "Internal application error: %s",
        type(error).__name__
    )

    return (
        "An internal error occurred. "
        "Please try again later."
    )


# ============================================================
# SECURITY STATUS
# ============================================================

def security_status() -> dict[str, Any]:
    """
    Return non-sensitive security configuration status.
    """

    return {
        "service": APP_NAME,
        "version": VERSION,

        "secret_configured": bool(
            SECRET_KEY
        ),

        "secret_length_valid": (
            len(SECRET_KEY) >= 32
            if SECRET_KEY
            else False
        ),

        "jwt_algorithm": JWT_ALGORITHM,

        "jwt_expiration_minutes": (
            JWT_EXPIRE_MINUTES
        ),

        "rate_limit": {
            "requests": RATE_LIMIT_REQUESTS,
            "window_seconds": (
                RATE_LIMIT_WINDOW_SECONDS
            )
        },

        "allowed_origins": (
            get_allowed_origins()
        ),

        "security_headers": list(
            SECURITY_HEADERS.keys()
        )
}

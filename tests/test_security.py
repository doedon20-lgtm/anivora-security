"""
AniVora Security test suite.
"""

import os

# Set a valid test secret before importing the application.
os.environ["ANIVORA_SECRET_KEY"] = (
    "test-secret-key-that-is-at-least-32-characters-long"
)

os.environ["ANIVORA_ALLOWED_HOSTS"] = (
    "testserver,localhost,127.0.0.1"
)

from fastapi.testclient import TestClient

from app.main import app
from app.security import (
    create_access_token,
    decode_access_token,
    generate_api_key,
    generate_request_id,
    generate_token,
    hash_api_key,
    hash_password,
    redact_sensitive_data,
    require_scope,
    validate_api_name,
    validate_prompt,
    validate_username,
    verify_api_key,
    verify_password,
)


client = TestClient(app)


# ============================================================
# BASIC APPLICATION TESTS
# ============================================================

def test_root():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "AniVora Security"
    assert data["status"] == "online"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["status"] == "healthy"


# ============================================================
# SECURITY MIDDLEWARE TESTS
# ============================================================

def test_request_id():
    response = client.get(
        "/v1/security/request"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["request_id"].startswith(
        "req_"
    )

    assert "X-Request-ID" in response.headers


def test_security_headers():
    response = client.get(
        "/v1/security/headers"
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "X-Content-Type-Options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "X-Frame-Options"
        ]
        == "DENY"
    )

    assert (
        "Content-Security-Policy"
        in response.headers
    )

    assert (
        "Referrer-Policy"
        in response.headers
    )

    assert (
        "Permissions-Policy"
        in response.headers
    )


# ============================================================
# SECURITY STATUS
# ============================================================

def test_security_status():
    response = client.get(
        "/v1/security/status"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    security = data["security"]

    assert security[
        "secret_configured"
    ] is True

    assert security[
        "secret_length_valid"
    ] is True

    assert (
        security["jwt_algorithm"]
        == "HS256"
    )

    assert (
        "Content-Security-Policy"
        in security["security_headers"]
    )


# ============================================================
# PASSWORD SECURITY
# ============================================================

def test_password_hashing():
    password = "StrongTestPassword123!"

    password_hash = hash_password(
        password
    )

    assert password_hash != password

    assert verify_password(
        password,
        password_hash,
    )

    assert not verify_password(
        "WrongPassword123!",
        password_hash,
    )


def test_short_password_rejected():
    try:
        hash_password("short")
        assert False
    except ValueError:
        assert True


# ============================================================
# API KEY SECURITY
# ============================================================

def test_api_key():
    api_key = generate_api_key()

    assert api_key.startswith(
        "av_"
    )

    key_hash = hash_api_key(
        api_key
    )

    assert verify_api_key(
        api_key,
        key_hash,
    )

    assert not verify_api_key(
        "av_invalid_key",
        key_hash,
    )


# ============================================================
# TOKEN GENERATION
# ============================================================

def test_secure_token():
    token = generate_token(32)

    assert isinstance(
        token,
        str,
    )

    assert len(token) > 20


def test_request_id_generation():
    request_id = (
        generate_request_id()
    )

    assert request_id.startswith(
        "req_"
    )


# ============================================================
# JWT
# ============================================================

def test_jwt():
    token = create_access_token(
        subject="usr_test123",
        scopes=[
            "read",
            "write",
        ],
    )

    assert isinstance(
        token,
        str,
    )

    payload = decode_access_token(
        token
    )

    assert (
        payload["sub"]
        == "usr_test123"
    )

    assert "read" in payload[
        "scopes"
    ]

    assert "write" in payload[
        "scopes"
    ]


# ============================================================
# AUTHORIZATION
# ============================================================

def test_scope_authorization():
    payload = {
        "sub": "usr_test",
        "scopes": [
            "projects:read",
            "projects:write",
        ],
    }

    require_scope(
        payload,
        "projects:read",
    )


def test_missing_scope_rejected():
    payload = {
        "sub": "usr_test",
        "scopes": [
            "projects:read",
        ],
    }

    try:
        require_scope(
            payload,
            "admin",
        )

        assert False

    except Exception as error:
        assert getattr(
            error,
            "status_code",
            None,
        ) == 403


# ============================================================
# INPUT VALIDATION
# ============================================================

def test_username_validation():
    assert (
        validate_username(
            "samuel_123"
        )
        == "samuel_123"
    )


def test_username_invalid():
    try:
        validate_username(
            "bad username!"
        )

        assert False

    except ValueError:
        assert True


def test_api_name_validation():
    assert (
        validate_api_name(
            "AniVora-API"
        )
        == "AniVora-API"
    )


def test_prompt_validation():
    prompt = (
        "Create a modern website."
    )

    assert (
        validate_prompt(prompt)
        == prompt
    )


# ============================================================
# REDACTION
# ============================================================

def test_sensitive_data_redaction():
    data = {
        "username": "samuel",
        "password": "secret",
        "api_key": "av_secret",
        "nested": {
            "token": "secret-token",
            "normal": "safe",
        },
    }

    result = redact_sensitive_data(
        data
    )

    assert (
        result["username"]
        == "samuel"
    )

    assert (
        result["password"]
        == "[REDACTED]"
    )

    assert (
        result["api_key"]
        == "[REDACTED]"
    )

    assert (
        result["nested"]["token"]
        == "[REDACTED]"
    )

    assert (
        result["nested"]["normal"]
        == "safe"
  )

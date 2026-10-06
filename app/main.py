"""
AniVora Security Service
========================

Main FastAPI application for the AniVora Security foundation.

This service provides:
    - Security status
    - Request IDs
    - Security headers
    - Rate limiting
    - Password hashing utilities
    - API-key utilities
    - JWT utilities
    - Input validation
    - Security event logging

Other AniVora services can eventually reuse the security
module from this repository.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.security import (
    APP_NAME,
    VERSION,
    ALLOWED_ORIGINS,
    add_security_headers,
    generate_request_id,
    security_event,
    security_status,
)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    description=(
        "Reusable security foundation for AniVora services."
    ),
    version=VERSION,
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Request-ID",
    ],
    expose_headers=[
        "X-Request-ID",
    ],
)


# ============================================================
# TRUSTED HOSTS
# ============================================================

# Development defaults.
#
# When deployed, replace these with the real AniVora domains
# through an environment variable/configuration system.
#
# We intentionally keep localhost available for development.

import os

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv(
        "ANIVORA_ALLOWED_HOSTS",
        "localhost,127.0.0.1",
    ).split(",")
    if host.strip()
]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)


# ============================================================
# SECURITY MIDDLEWARE
# ============================================================

@app.middleware("http")
async def security_middleware(
    request: Request,
    call_next,
):
    """
    Security middleware executed for every HTTP request.
    """

    start_time = time.perf_counter()

    request_id = generate_request_id()

    request.state.request_id = request_id

    try:
        # ----------------------------------------------------
        # Basic request protection
        # ----------------------------------------------------

        # The actual rate limiter is handled here directly
        # through the reusable security function.
        from app.security import enforce_rate_limit

        enforce_rate_limit(request)

        # ----------------------------------------------------
        # Process request
        # ----------------------------------------------------

        response = await call_next(request)

        # ----------------------------------------------------
        # Security response headers
        # ----------------------------------------------------

        add_security_headers(response)

        response.headers[
            "X-Request-ID"
        ] = request_id

        # Prevent browsers from MIME-sniffing responses.
        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        # Prevent caching of sensitive security endpoints.
        if request.url.path.startswith(
            "/v1/security"
        ):
            response.headers[
                "Cache-Control"
            ] = (
                "no-store, "
                "no-cache, "
                "must-revalidate"
            )

        # ----------------------------------------------------
        # Request timing
        # ----------------------------------------------------

        duration = (
            time.perf_counter()
            - start_time
        )

        response.headers[
            "X-Request-Duration"
        ] = f"{duration:.6f}"

        return response

    except Exception as error:

        # Never expose internal exception details
        # through the security logs.
        security_event(
            event="request_processing_error",
            request=request,
            success=False,
            details={
                "error_type": type(
                    error
                ).__name__,
                "path": request.url.path,
                "method": request.method,
            },
        )

        raise


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "name": APP_NAME,
        "version": VERSION,
        "status": "online",
        "service": "security",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return {
        "success": True,
        "service": APP_NAME,
        "status": "healthy",
        "version": VERSION,
    }


# ============================================================
# SECURITY STATUS
# ============================================================

@app.get("/v1/security/status")
async def get_security_status():
    """
    Return safe security configuration information.

    Secrets themselves are NEVER returned.
    """

    status = security_status()

    return {
        "success": True,
        "security": status,
    }


# ============================================================
# REQUEST-ID TEST
# ============================================================

@app.get("/v1/security/request")
async def security_request(
    request: Request,
):
    """
    Verify that request IDs are being generated.
    """

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    return {
        "success": True,
        "request_id": request_id,
        "message": (
            "Security middleware is active."
        ),
    }


# ============================================================
# SECURITY HEADER TEST
# ============================================================

@app.get("/v1/security/headers")
async def security_headers():
    """
    Endpoint used to verify security headers.
    """

    return {
        "success": True,
        "message": (
            "Security headers are applied "
            "by middleware."
        ),
    }


# ============================================================
# RATE LIMIT TEST
# ============================================================

@app.get("/v1/security/rate-limit")
async def rate_limit_status(
    request: Request,
):
    """
    Show the current rate-limit allowance
    for the requesting client.

    This does not expose the client's raw
    security credentials.
    """

    from app.security import (
        get_client_identifier,
        rate_limiter,
    )

    identifier = get_client_identifier(
        request
    )

    remaining = rate_limiter.remaining(
        identifier
    )

    return {
        "success": True,
        "remaining_requests": remaining,
    }


# ============================================================
# SECURITY EVENT TEST
# ============================================================

@app.post("/v1/security/test-event")
async def test_security_event(
    request: Request,
):
    """
    Generate a harmless security audit event.

    This endpoint exists for testing the security
    logging system during development.
    """

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    security_event(
        event="security_test_event",
        request=request,
        success=True,
        details={
            "test": True,
            "request_id": request_id,
        },
    )

    return {
        "success": True,
        "message": (
            "Security event recorded."
        ),
        "request_id": request_id,
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    """
    Application startup.

    Never print secrets or authentication tokens.
    """

    print(
        f"{APP_NAME} v{VERSION} starting..."
    )

    status = security_status()

    print(
        "Security configuration loaded."
    )

    print(
        "Secret configured:",
        status["secret_configured"],
    )

    print(
        "JWT algorithm:",
        status["jwt_algorithm"],
    )

    print(
        "Rate limit:",
        (
            f"{status['rate_limit']['requests']} "
            f"requests / "
            f"{status['rate_limit']['window_seconds']} "
            f"seconds"
        ),
    )


# ============================================================
# SHUTDOWN
# ============================================================

@app.on_event("shutdown")
async def shutdown_event():
    """
    Application shutdown.
    """

    print(
        f"{APP_NAME} shutting down..."
  )

"""
AniVora Security server launcher.
"""

import os

import uvicorn


HOST = os.getenv(
    "ANIVORA_SECURITY_HOST",
    "0.0.0.0",
)

PORT = int(
    os.getenv(
        "ANIVORA_SECURITY_PORT",
        "8010",
    )
)


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        reload=False,
    )

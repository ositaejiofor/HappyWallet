"""
HappyWallet Portable Settings.

Configuration for portable desktop / USB / cold-wallet operation.

Design goals:
    - local-first operation
    - USB/removable-storage compatibility
    - offline signing support
    - no private-key persistence
    - no private-key network transfer
    - blockchain broadcasting disabled by default
    - isolated portable database
    - no production secrets hardcoded
"""

import os
from pathlib import Path

from dotenv import load_dotenv

from .base import *  # noqa: F403,F401


# ============================================================================
# ENVIRONMENT
# ============================================================================

ENVIRONMENT = "portable"

WALLET_ENVIRONMENT = "portable"

load_dotenv(BASE_DIR / ".env")  # noqa: F405


# ============================================================================
# ENVIRONMENT HELPERS
# ============================================================================

def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable."""

    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def env_list(
    name: str,
    default: str = "",
) -> list[str]:
    """Read a comma-separated environment variable."""

    return [
        value.strip()
        for value in os.getenv(name, default).split(",")
        if value.strip()
    ]


def env_path(
    name: str,
    default: Path,
) -> Path:
    """Read and normalize a filesystem path."""

    value = os.getenv(name)

    if not value:
        return default

    return Path(value).expanduser()


# ============================================================================
# SECURITY
# ============================================================================

DEBUG = False

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "portable-development-key-change-before-release",
)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    "127.0.0.1,localhost",
)


# ============================================================================
# DATABASE
# ============================================================================

# Portable mode deliberately does NOT use DB_NAME from the normal
# development .env configuration.
#
# Default:
#
#     <HappyWallet>/data/happywallet.sqlite3
#
# This keeps portable storage isolated from the development database.

PORTABLE_DATA_DIR = env_path(
    "PORTABLE_DATA_DIR",
    BASE_DIR / "data",  # noqa: F405
)

PORTABLE_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

PORTABLE_DB_PATH = env_path(
    "PORTABLE_DB_PATH",
    PORTABLE_DATA_DIR / "happywallet.sqlite3",
)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": PORTABLE_DB_PATH,
    },
}


# ============================================================================
# STATIC FILES
# ============================================================================

STATIC_URL = "/static/"

STATIC_ROOT = BASE_DIR / "staticfiles"  # noqa: F405

STATICFILES_DIRS = [
    BASE_DIR / "static",  # noqa: F405
]


# ============================================================================
# MEDIA FILES
# ============================================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = PORTABLE_DATA_DIR / "media"


# ============================================================================
# PORTABLE SECURITY
# ============================================================================

SECURE_SSL_REDIRECT = False

SESSION_COOKIE_SECURE = False

CSRF_COOKIE_SECURE = False

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_REFERRER_POLICY = "same-origin"


# ============================================================================
# EMAIL
# ============================================================================

EMAIL_BACKEND = (
    "django.core.mail.backends.console.EmailBackend"
)


# ============================================================================
# CORS
# ============================================================================

# Portable wallet UI should not expose a permissive CORS policy.

CORS_ALLOW_ALL_ORIGINS = False


# ============================================================================
# CELERY
# ============================================================================

# Celery is available for local portable workflows, but Redis is not required
# for the Django application itself.

CELERY_BROKER_URL = os.getenv(
    "CELERY_BROKER_URL",
    "redis://127.0.0.1:6379/0",
)

CELERY_RESULT_BACKEND = os.getenv(
    "CELERY_RESULT_BACKEND",
    "redis://127.0.0.1:6379/0",
)


# ============================================================================
# CHANNELS
# ============================================================================

# In-memory channels keep portable mode independent of Redis for WebSockets.

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}


# ============================================================================
# BLOCKCHAIN RPC
# ============================================================================

ETHEREUM_RPC_URL = os.getenv(
    "ETHEREUM_RPC_URL",
    "",
)

BITCOIN_RPC_URL = os.getenv(
    "BITCOIN_RPC_URL",
    "",
)

TRON_RPC_URL = os.getenv(
    "TRON_RPC_URL",
    "",
)


# ============================================================================
# SUPPORTED NETWORKS
# ============================================================================

SUPPORTED_BLOCKCHAIN_NETWORKS = {
    "ethereum",
    "bitcoin",
    "tron",
}


# ============================================================================
# WALLET DEFAULTS
# ============================================================================

DEFAULT_WALLET_NETWORK = os.getenv(
    "DEFAULT_WALLET_NETWORK",
    "ethereum",
)

DEFAULT_WALLET_ASSET = os.getenv(
    "DEFAULT_WALLET_ASSET",
    "USDT",
)


# ============================================================================
# TRANSACTION SAFETY
# ============================================================================

WALLET_REQUIRE_CONFIRMATION = env_bool(
    "WALLET_REQUIRE_CONFIRMATION",
    True,
)

# Broadcasting remains disabled unless explicitly enabled.
#
# For an actual cold-wallet deployment, keep this False.

WALLET_ALLOW_BROADCAST = env_bool(
    "WALLET_ALLOW_BROADCAST",
    False,
)


# ============================================================================
# OFFLINE SIGNING
# ============================================================================

OFFLINE_SIGNING_ENABLED = True

USB_SIGNING_ENABLED = True

PRIVATE_KEY_PERSISTENCE_ALLOWED = False

PRIVATE_KEY_LOGGING_ALLOWED = False

PRIVATE_KEY_NETWORK_TRANSFER_ALLOWED = False


# ============================================================================
# PORTABLE WALLET STORAGE
# ============================================================================

# Wallet secrets/private keys must never be stored by Django settings.

WALLET_STORAGE_DIR = PORTABLE_DATA_DIR / "wallet"

WALLET_STORAGE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================================
# LOGGING
# ============================================================================

LOGGING["loggers"]["apps"]["level"] = "INFO"  # noqa: F405
LOGGING["loggers"]["django"]["level"] = "WARNING"  # noqa: F405
LOGGING["handlers"]["console"]["level"] = "INFO"  # noqa: F405

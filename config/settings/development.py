"""
HappyWallet Development Settings.

Development-only configuration.

Base configuration is inherited from:
    config.settings.base

This module provides:
    - local development defaults
    - environment-variable loading
    - SQLite development database
    - local static/media configuration
    - development security settings
    - blockchain RPC configuration
    - wallet safety controls
    - development logging
"""

import os

from dotenv import load_dotenv

from .base import *  # noqa: F403,F401


# ============================================================================
# ENVIRONMENT
# ============================================================================

ENVIRONMENT = "development"


# ============================================================================
# ENVIRONMENT FILE
# ============================================================================

load_dotenv(BASE_DIR / ".env")  # noqa: F405


# ============================================================================
# ENVIRONMENT HELPERS
# ============================================================================

def env_bool(name: str, default: bool = False) -> bool:
    """
    Read a boolean value from the environment.
    """
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def env_list(name: str, default: str = "") -> list[str]:
    """
    Read a comma-separated environment variable as a list.
    """
    return [
        value.strip()
        for value in os.getenv(name, default).split(",")
        if value.strip()
    ]


# ============================================================================
# SECURITY
# ============================================================================

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "django-insecure-happywallet-development-only",
)

DEBUG = env_bool(
    "DJANGO_DEBUG",
    True,
)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    "127.0.0.1,localhost",
)


# ============================================================================
# DATABASE
# ============================================================================

DATABASES = {
    "default": {
        "ENGINE": os.getenv(
            "DB_ENGINE",
            "django.db.backends.sqlite3",
        ),
        "NAME": os.getenv(
            "DB_NAME",
            str(BASE_DIR / "db.sqlite3"),  # noqa: F405
        ),
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

MEDIA_ROOT = BASE_DIR / "media"  # noqa: F405


# ============================================================================
# DEVELOPMENT SECURITY
# ============================================================================

# Local development uses HTTP.
# These MUST NOT be enabled for the desktop development server.

SECURE_SSL_REDIRECT = False

SESSION_COOKIE_SECURE = False

CSRF_COOKIE_SECURE = False

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"


# ============================================================================
# EMAIL
# ============================================================================

EMAIL_BACKEND = (
    "django.core.mail.backends.console.EmailBackend"
)


# ============================================================================
# CORS
# ============================================================================

CORS_ALLOW_ALL_ORIGINS = env_bool(
    "CORS_ALLOW_ALL_ORIGINS",
    True,
)


# ============================================================================
# CELERY
# ============================================================================

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
# TRANSACTION / WALLET DEVELOPMENT CONTROLS
# ============================================================================

WALLET_ENVIRONMENT = "development"

WALLET_REQUIRE_CONFIRMATION = env_bool(
    "WALLET_REQUIRE_CONFIRMATION",
    True,
)

# Broadcasting is disabled by default.
#
# To deliberately enable it through .env:
#
# WALLET_ALLOW_BROADCAST=True

WALLET_ALLOW_BROADCAST = env_bool(
    "WALLET_ALLOW_BROADCAST",
    False,
)


# ============================================================================
# SUPPORTED BLOCKCHAIN NETWORKS
# ============================================================================

SUPPORTED_BLOCKCHAIN_NETWORKS = {
    "ethereum",
    "bitcoin",
    "tron",
}


# ============================================================================
# DEVELOPMENT DEFAULTS
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
# LOGGING
# ============================================================================

LOGGING["loggers"]["apps"]["level"] = "DEBUG"  # noqa: F405
LOGGING["loggers"]["django"]["level"] = "INFO"  # noqa: F405
LOGGING["handlers"]["console"]["level"] = "DEBUG"  # noqa: F405


"""
HappyWallet - Base Django Settings.

This module contains settings shared by all environments.

Environment-specific modules should override values where appropriate:

    config.settings.development
    config.settings.production
    config.settings.portable

Security principles
-------------------

1. Secrets come from environment variables.
2. No blockchain credentials are hard-coded.
3. Base settings remain environment-neutral.
4. Production settings should explicitly enable HTTPS/security controls.
5. Network timeouts and resource limits are bounded.
6. Application services should read configuration through Django settings,
   not directly from .env files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from dotenv import load_dotenv


# ============================================================================
# PATHS
# ============================================================================

BASE_DIR: Final[Path] = (
    Path(__file__).resolve().parent.parent.parent
)

ENV_FILE: Final[Path] = BASE_DIR / ".env"

# Load local environment variables when available.
#
# Environment variables already exported by the operating system are
# preserved by python-dotenv's default override=False behavior.
load_dotenv(ENV_FILE)


# ============================================================================
# ENVIRONMENT HELPERS
# ============================================================================


_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {
        "0",
        "false",
        "no",
        "n",
        "off",
    }
)


def env_str(
    name: str,
    default: str = "",
    *,
    required: bool = False,
) -> str:
    """
    Read a normalized string environment variable.

    Parameters
    ----------
    name:
        Environment variable name.

    default:
        Value returned when the variable is absent.

    required:
        If True, an empty/missing value raises RuntimeError.

    Returns
    -------
    str
        Stripped environment value.
    """

    value = os.getenv(name)

    if value is None:
        value = default

    value = str(value).strip()

    if required and not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is not configured."
        )

    return value


def env_bool(
    name: str,
    default: bool = False,
) -> bool:
    """
    Read a boolean environment variable safely.

    Unknown values intentionally fall back to ``default`` rather than
    silently enabling a security-sensitive feature.
    """

    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    return default


def env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """
    Read and validate an integer environment variable.

    Invalid values fall back to the supplied default.

    Values can optionally be bounded by ``minimum`` and ``maximum``.
    """

    value = os.getenv(name)

    if value is None:
        result = default
    else:
        try:
            result = int(value.strip())
        except (TypeError, ValueError):
            result = default

    if minimum is not None:
        result = max(result, minimum)

    if maximum is not None:
        result = min(result, maximum)

    return result


def env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Read and safely bound a floating-point environment variable."""

    value = os.getenv(name)

    if value is None:
        result = default
    else:
        try:
            result = float(value.strip())
        except (TypeError, ValueError):
            result = default

    if minimum is not None:
        result = max(result, minimum)

    if maximum is not None:
        result = min(result, maximum)

    return result


def env_list(
    name: str,
    default: str = "",
) -> list[str]:
    """
    Read a comma-separated environment variable.

    Empty values are removed and surrounding whitespace is stripped.
    """

    value = env_str(
        name,
        default,
    )

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


# ============================================================================
# ENVIRONMENT
# ============================================================================

DJANGO_ENVIRONMENT = env_str(
    "DJANGO_ENVIRONMENT",
    "development",
).lower()


# ============================================================================
# SECURITY
# ============================================================================

# Do not use a real production secret in this file.
#
# Environment-specific settings should require a real secret in production.
SECRET_KEY = env_str(
    "DJANGO_SECRET_KEY",
    "django-insecure-development-only-change-me",
)

DEBUG = env_bool(
    "DJANGO_DEBUG",
    default=False,
)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
)

COINGECKO_API_KEY = os.getenv(
    "COINGECKO_API_KEY",
    "",
)
KRAKEN_API_KEY = os.getenv(
    "KRAKEN_API_KEY",
    "",
)

KRAKEN_API_SECRET = os.getenv(
    "KRAKEN_API_SECRET",
    "",
)

KRAKEN_LIVE_TRADING_ENABLED = env_bool(
    "KRAKEN_LIVE_TRADING_ENABLED",
    default=False,
)

# ============================================================================
# APPLICATIONS
# ============================================================================

INSTALLED_APPS = [
    # ------------------------------------------------------------------------
    # Django
    # ------------------------------------------------------------------------

    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # ------------------------------------------------------------------------
    # HappyWallet
    # ------------------------------------------------------------------------

    "apps.accounts",
    "apps.blockchain",
    "apps.core",
    "apps.security",
    "apps.wallet",
    "apps.ledger",
    "apps.transaction",
    "apps.portfolio",
    "apps.market",
    "apps.dashboard",
    "apps.usb_manager",
    "apps.token_scanner",
    "apps.trading",
]


# ============================================================================
# MIDDLEWARE
# ============================================================================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",

    "django.middleware.common.CommonMiddleware",

    "django.middleware.csrf.CsrfViewMiddleware",

    "django.contrib.auth.middleware.AuthenticationMiddleware",

    "django.contrib.messages.middleware.MessageMiddleware",

    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# ============================================================================
# URL CONFIGURATION
# ============================================================================

ROOT_URLCONF = "config.urls"


# ============================================================================
# TEMPLATES
# ============================================================================

TEMPLATES = [
    {
        "BACKEND": (
            "django.template.backends.django.DjangoTemplates"
        ),

        "DIRS": [
            BASE_DIR / "templates",
        ],

        "APP_DIRS": True,

        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",

                "django.contrib.auth.context_processors.auth",

                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


# ============================================================================
# WSGI / ASGI
# ============================================================================

WSGI_APPLICATION = "config.wsgi.application"

ASGI_APPLICATION = "config.asgi.application"


# ============================================================================
# DATABASE
# ============================================================================

# Database configuration is deliberately environment-specific.
#
# Examples:
#
#     config.settings.development
#     config.settings.production
#     config.settings.portable
#
DATABASES: dict = {}


# ============================================================================
# PASSWORD VALIDATION
# ============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]


# ============================================================================
# INTERNATIONALIZATION
# ============================================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = env_str(
    "DJANGO_TIME_ZONE",
    "UTC",
)

USE_I18N = True

USE_TZ = True


# ============================================================================
# STATIC FILES
# ============================================================================

STATIC_URL = env_str(
    "STATIC_URL",
    "/static/",
)

STATIC_ROOT = BASE_DIR / "staticfiles"

STATICFILES_DIRS = [
    BASE_DIR / "static",
]


# ============================================================================
# MEDIA FILES
# ============================================================================

MEDIA_URL = env_str(
    "MEDIA_URL",
    "/media/",
)

MEDIA_ROOT = BASE_DIR / "media"


# ============================================================================
# DEFAULT PRIMARY KEY
# ============================================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ============================================================================
# AUTHENTICATION
# ============================================================================

AUTH_USER_MODEL = "accounts.User"

LOGIN_URL = "/accounts/login/"

LOGIN_REDIRECT_URL = "/"

LOGOUT_REDIRECT_URL = "/accounts/login/"


# ============================================================================
# SESSION SECURITY
# ============================================================================

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"

# These remain False in base settings so local HTTP development continues
# to work. Production settings should override them to True.
SESSION_COOKIE_SECURE = False

CSRF_COOKIE_SECURE = False

SESSION_COOKIE_NAME = "happywallet_session"

CSRF_COOKIE_NAME = "happywallet_csrf"

SESSION_COOKIE_AGE = env_int(
    "SESSION_COOKIE_AGE",
    60 * 60 * 24 * 7,
    minimum=300,
    maximum=60 * 60 * 24 * 365,
)

SESSION_SAVE_EVERY_REQUEST = env_bool(
    "SESSION_SAVE_EVERY_REQUEST",
    default=False,
)


# ============================================================================
# GENERAL SECURITY
# ============================================================================

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_REFERRER_POLICY = "same-origin"

SECURE_BROWSER_XSS_FILTER = False

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"


# ============================================================================
# HTTPS SECURITY
# ============================================================================

# Production settings should enable these explicitly.
SECURE_SSL_REDIRECT = env_bool(
    "SECURE_SSL_REDIRECT",
    default=False,
)

SECURE_HSTS_SECONDS = env_int(
    "SECURE_HSTS_SECONDS",
    0,
    minimum=0,
)

SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=False,
)

SECURE_HSTS_PRELOAD = env_bool(
    "SECURE_HSTS_PRELOAD",
    default=False,
)

SECURE_PROXY_SSL_HEADER = None


# ============================================================================
# CSRF TRUST
# ============================================================================

CSRF_TRUSTED_ORIGINS = env_list(
    "DJANGO_CSRF_TRUSTED_ORIGINS",
)


# ============================================================================
# WALLET / BLOCKCHAIN
# ============================================================================

SUPPORTED_BLOCKCHAIN_NETWORKS: Final[frozenset[str]] = frozenset(
    {
        "ethereum",
        "bitcoin",
        "tron",
    }
)

DEFAULT_WALLET_NETWORK = env_str(
    "DEFAULT_WALLET_NETWORK",
    "ethereum",
).lower()

DEFAULT_WALLET_ASSET = env_str(
    "DEFAULT_WALLET_ASSET",
    "USDT",
).upper()


# ============================================================================
# BLOCKCHAIN RPC
# ============================================================================

# RPC endpoints MUST come from environment configuration.
#
# Never put API keys directly in Python source code.

ETHEREUM_RPC_URL = env_str(
    "ETHEREUM_RPC_URL",
)

BITCOIN_RPC_URL = env_str(
    "BITCOIN_RPC_URL",
)

TRON_RPC_URL = env_str(
    "TRON_RPC_URL",
)


# ============================================================================
# BLOCKCHAIN NETWORK IDS
# ============================================================================

ETHEREUM_CHAIN_ID = env_int(
    "ETHEREUM_CHAIN_ID",
    1,
    minimum=1,
)

BITCOIN_CHAIN_ID = None

TRON_CHAIN_ID = None


# ============================================================================
# BLOCKCHAIN CONNECTION LIMITS
# ============================================================================

# Generic RPC timeout used by blockchain services.
#
# 15 seconds is a reasonable upper-level default, but individual adapters
# may use a lower timeout when appropriate.
BLOCKCHAIN_RPC_TIMEOUT = env_int(
    "BLOCKCHAIN_RPC_TIMEOUT",
    15,
    minimum=1,
    maximum=60,
)


# Ethereum history adapter supports its own bounded HTTP timeout.
#
# This fixes the previous situation where the application had
# BLOCKCHAIN_RPC_TIMEOUT but the Ethereum history adapter had no
# configuration value of its own.
ETHEREUM_RPC_TIMEOUT = env_int(
    "ETHEREUM_RPC_TIMEOUT",
    10,
    minimum=1,
    maximum=30,
)


# ============================================================================
# TRANSACTION HISTORY
# ============================================================================

# Number of recent blocks inspected by the transaction history service.
#
# IMPORTANT:
# Ethereum's standard JSON-RPC API does not provide an efficient
# "transactions for address" endpoint. Scanning too many blocks can
# therefore generate substantial RPC traffic.
DEFAULT_TRANSACTION_HISTORY_BLOCK_LIMIT = 25

MAX_TRANSACTION_HISTORY_BLOCK_LIMIT = 10_000

TRANSACTION_HISTORY_BLOCK_LIMIT = env_int(
    "TRANSACTION_HISTORY_BLOCK_LIMIT",
    DEFAULT_TRANSACTION_HISTORY_BLOCK_LIMIT,
    minimum=1,
    maximum=MAX_TRANSACTION_HISTORY_BLOCK_LIMIT,
)


# Ethereum adapter has a deliberately smaller hard safety boundary.
ETHEREUM_HISTORY_BLOCK_LIMIT = env_int(
    "ETHEREUM_HISTORY_BLOCK_LIMIT",
    25,
    minimum=1,
    maximum=100,
)


# ============================================================================
# TRANSACTION / BROADCAST SAFETY
# ============================================================================

WALLET_ALLOW_BROADCAST = env_bool(
    "WALLET_ALLOW_BROADCAST",
    default=False,
)

WALLET_REQUIRE_CONFIRMATION = env_bool(
    "WALLET_REQUIRE_CONFIRMATION",
    default=True,
)


# ============================================================================
# RPC RETRY / RESILIENCE
# ============================================================================

RPC_MAX_RETRIES = env_int(
    "RPC_MAX_RETRIES",
    2,
    minimum=0,
    maximum=5,
)

RPC_RETRY_BACKOFF_SECONDS = env_float(
    "RPC_RETRY_BACKOFF_SECONDS",
    0.5,
    minimum=0.0,
    maximum=10.0,
)


# ============================================================================
# REDIS / CELERY
# ============================================================================

REDIS_URL = env_str(
    "REDIS_URL",
    "redis://127.0.0.1:6379/0",
)

CELERY_BROKER_URL = env_str(
    "CELERY_BROKER_URL",
    REDIS_URL,
)

CELERY_RESULT_BACKEND = env_str(
    "CELERY_RESULT_BACKEND",
    REDIS_URL,
)

CELERY_ACCEPT_CONTENT = [
    "json",
]

CELERY_TASK_SERIALIZER = "json"

CELERY_RESULT_SERIALIZER = "json"

CELERY_TIMEZONE = TIME_ZONE

CELERY_ENABLE_UTC = True


# ============================================================================
# CACHE
# ============================================================================

CACHE_URL = env_str(
    "CACHE_URL",
    REDIS_URL,
)

CACHES = {
    "default": {
        "BACKEND": (
            "django.core.cache.backends.locmem.LocMemCache"
        ),
        "LOCATION": "happywallet-default-cache",
    },
}


# ============================================================================
# EMAIL
# ============================================================================

EMAIL_BACKEND = env_str(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend",
)

EMAIL_HOST = env_str(
    "EMAIL_HOST",
)

EMAIL_PORT = env_int(
    "EMAIL_PORT",
    587,
    minimum=1,
    maximum=65535,
)

EMAIL_HOST_USER = env_str(
    "EMAIL_HOST_USER",
)

EMAIL_HOST_PASSWORD = env_str(
    "EMAIL_HOST_PASSWORD",
)

EMAIL_USE_TLS = env_bool(
    "EMAIL_USE_TLS",
    default=True,
)

EMAIL_USE_SSL = env_bool(
    "EMAIL_USE_SSL",
    default=False,
)

DEFAULT_FROM_EMAIL = env_str(
    "DEFAULT_FROM_EMAIL",
    "HappyWallet <no-reply@example.com>",
)

SERVER_EMAIL = env_str(
    "SERVER_EMAIL",
    DEFAULT_FROM_EMAIL,
)


# ============================================================================
# APPLICATION URL
# ============================================================================

SITE_URL = env_str(
    "SITE_URL",
    "http://127.0.0.1:8000",
).rstrip("/")


# ============================================================================
# CORS
# ============================================================================

# These settings are harmless even if django-cors-headers is not installed.
CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS",
)

CORS_ALLOW_CREDENTIALS = env_bool(
    "CORS_ALLOW_CREDENTIALS",
    default=False,
)


# ============================================================================
# LOGGING
# ============================================================================

LOG_LEVEL = env_str(
    "LOG_LEVEL",
    "INFO",
).upper()

LOGGING = {
    "version": 1,

    "disable_existing_loggers": False,

    "formatters": {
        "verbose": {
            "format": (
                "{asctime} {levelname} "
                "{name} {message}"
            ),
            "style": "{",
        },

        "simple": {
            "format": (
                "{levelname} {message}"
            ),
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },

    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },

        "apps": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },

        # Blockchain providers can produce useful operational warnings,
        # but credentials and raw RPC payloads must never be logged.
        "apps.transaction": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },

        "apps.blockchain": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}


# ============================================================================
# DEVELOPMENT / PRODUCTION GUARDS
# ============================================================================

# Base settings intentionally do not raise here because this module is also
# imported by environment-specific settings modules.
#
# config.settings.production should enforce:
#
#     DEBUG = False
#     SECRET_KEY must be supplied
#     ALLOWED_HOSTS must not be empty
#     SESSION_COOKIE_SECURE = True
#     CSRF_COOKIE_SECURE = True
#     SECURE_SSL_REDIRECT = True
#     HSTS enabled
#
# Keeping those requirements in production.py avoids breaking local
# development and portable/offline operation.

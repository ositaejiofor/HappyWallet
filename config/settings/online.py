"""
HappyWallet — Online / Connected Environment
=============================================

Production-oriented Django settings for the Internet-connected
HappyWallet deployment.

Security rules:
- Never store wallet seeds or private keys in Django settings.
- Never store passwords, API keys, or credentials in source code.
- Secrets must come from environment variables.
- The online server must not possess usable private wallet keys.
- Transaction signing must remain delegated to the offline wallet.
"""

import os
from pathlib import Path

from .base import *  # noqa: F401,F403


# ============================================================
# ENVIRONMENT
# ============================================================

ENVIRONMENT = "online"

DEBUG = os.getenv("DJANGO_DEBUG", "False").strip().lower() == "true"

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "").strip()

if not SECRET_KEY:
    raise RuntimeError(
        "DJANGO_SECRET_KEY must be configured in the environment."
    )


# ============================================================
# HELPERS
# ============================================================

def env_list(name, default=None):
    """
    Read a comma-separated environment variable into a list.
    """
    value = os.getenv(name)

    if value is None:
        return list(default or [])

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def env_bool(name, default=False):
    """
    Safely read a boolean environment variable.
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


def env_int(name, default):
    """
    Safely read an integer environment variable.
    """
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be a valid integer."
        ) from exc


# ============================================================
# HOST CONFIGURATION
# ============================================================

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    default=[
        "127.0.0.1",
        "localhost",
    ],
)


# ============================================================
# APPLICATION URL
# ============================================================

APP_URL = os.getenv(
    "APP_URL",
    "http://127.0.0.1:8000",
).strip().rstrip("/")


# ============================================================
# CSRF
# ============================================================

CSRF_TRUSTED_ORIGINS = env_list(
    "DJANGO_CSRF_TRUSTED_ORIGINS",
)


# ============================================================
# PRODUCTION SECURITY
# ============================================================

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_REFERRER_POLICY = (
    "strict-origin-when-cross-origin"
)

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG


# ============================================================
# HTTPS SECURITY
# ============================================================

if not DEBUG:
    SECURE_SSL_REDIRECT = True

    SECURE_HSTS_SECONDS = env_int(
        "SECURE_HSTS_SECONDS",
        31536000,
    )

    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

    # Required when running behind a trusted HTTPS reverse proxy.
    SECURE_PROXY_SSL_HEADER = (
        "HTTP_X_FORWARDED_PROTO",
        "https",
    )
else:
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False


# ============================================================
# CORS
# ============================================================

CORS_ALLOW_ALL_ORIGINS = False

CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS",
)


# ============================================================
# EMAIL
# ============================================================

EMAIL_BACKEND = os.getenv(
    "DJANGO_EMAIL_BACKEND",
    "django.core.mail.backends.smtp.EmailBackend",
)

EMAIL_HOST = os.getenv(
    "EMAIL_HOST",
    "",
).strip()

EMAIL_PORT = env_int(
    "EMAIL_PORT",
    587,
)

EMAIL_USE_TLS = env_bool(
    "EMAIL_USE_TLS",
    True,
)

EMAIL_USE_SSL = env_bool(
    "EMAIL_USE_SSL",
    False,
)

EMAIL_HOST_USER = os.getenv(
    "EMAIL_HOST_USER",
    "",
).strip()

EMAIL_HOST_PASSWORD = os.getenv(
    "EMAIL_HOST_PASSWORD",
    "",
)

DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL",
    "HappyWallet <noreply@example.com>",
).strip()


# ============================================================
# STATIC FILES
# ============================================================

STATIC_ROOT = Path(
    os.getenv(
        "DJANGO_STATIC_ROOT",
        str(BASE_DIR / "staticfiles"),
    )
)


# ============================================================
# MEDIA FILES
# ============================================================

MEDIA_ROOT = Path(
    os.getenv(
        "DJANGO_MEDIA_ROOT",
        str(BASE_DIR / "media"),
    )
)


# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = os.getenv(
    "DJANGO_LOG_LEVEL",
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

        "happywallet": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}


# ============================================================
# HAPPY WALLET ONLINE MODE
# ============================================================

WALLET_ONLINE_MODE = True


# ============================================================
# COLD-WALLET SECURITY BOUNDARY
# ============================================================

# The online application must NEVER have access to usable
# private wallet keys.

ALLOW_ONLINE_PRIVATE_KEY_ACCESS = False

# The online server must never sign cold-wallet transactions.

ALLOW_ONLINE_TRANSACTION_SIGNING = False

# USB signing is delegated to the offline wallet workflow.

ALLOW_USB_SIGNING = True

REQUIRE_OFFLINE_SIGNING = True


# ============================================================
# TRANSACTION SECURITY
# ============================================================

WALLET_ALLOW_BROADCAST = env_bool(
    "WALLET_ALLOW_BROADCAST",
    False,
)

WALLET_REQUIRE_CONFIRMATION = True

WALLET_REQUIRE_UNLOCK = True

REQUIRE_TRANSACTION_CONFIRMATION = True

REQUIRE_DESTINATION_VERIFICATION = True


# ============================================================
# MARKET / BLOCKCHAIN DATA
# ============================================================

MARKET_DATA_ENABLED = True

BLOCKCHAIN_DATA_ENABLED = True

MARKET_API_URL = os.getenv(
    "MARKET_API_URL",
    "",
).strip()

BLOCKCHAIN_API_URL = os.getenv(
    "BLOCKCHAIN_API_URL",
    "",
).strip()


# ============================================================
# AUDIT / SECURITY LOGGING
# ============================================================

AUDIT_LOGGING_ENABLED = True

SECURITY_EVENT_LOGGING_ENABLED = True

# Never write wallet seeds, private keys, passwords,
# recovery phrases or PINs to logs.

AUDIT_LOG_SENSITIVE_DATA = False

WALLET_DISABLE_SENSITIVE_LOGGING = True


# ============================================================
# PASSWORD SECURITY
# ============================================================

PASSWORD_RESET_TIMEOUT = env_int(
    "PASSWORD_RESET_TIMEOUT",
    3600,
)


# ============================================================
# ADMIN
# ============================================================

ADMIN_URL = os.getenv(
    "DJANGO_ADMIN_URL",
    "admin/",
).strip()

if not ADMIN_URL.startswith("/"):
    ADMIN_URL = "/" + ADMIN_URL

if not ADMIN_URL.endswith("/"):
    ADMIN_URL += "/"


# ============================================================
# CELERY / REDIS
# ============================================================

CELERY_BROKER_URL = os.getenv(
    "CELERY_BROKER_URL",
    "redis://127.0.0.1:6379/0",
).strip()

CELERY_RESULT_BACKEND = os.getenv(
    "CELERY_RESULT_BACKEND",
    "redis://127.0.0.1:6379/0",
).strip()


# ============================================================
# DEVELOPMENT CONTROLS
# ============================================================

DEVELOPMENT_TOOLS = False


# ============================================================
# PRODUCTION VALIDATION
# ============================================================

if not DEBUG:

    if SECRET_KEY in {
        "change-this-to-a-long-random-secret-key",
        "replace-this-with-a-long-random-secret",
        "your-secret-key",
        "change-me",
        "changeme",
    }:
        raise RuntimeError(
            "A strong DJANGO_SECRET_KEY must be configured "
            "for the online environment."
        )

    if len(SECRET_KEY) < 50:
        raise RuntimeError(
            "DJANGO_SECRET_KEY is too short. "
            "Use a long random secret key."
        )

    if not ALLOWED_HOSTS:
        raise RuntimeError(
            "DJANGO_ALLOWED_HOSTS must contain at least "
            "one trusted host."
        )

    if not APP_URL:
        raise RuntimeError(
            "APP_URL must be configured."
        )


# ============================================================
# FINAL SAFETY ASSERTIONS
# ============================================================

if ALLOW_ONLINE_PRIVATE_KEY_ACCESS:
    raise RuntimeError(
        "Online private-key access is prohibited."
    )

if ALLOW_ONLINE_TRANSACTION_SIGNING:
    raise RuntimeError(
        "Online transaction signing is prohibited."
    )

if not REQUIRE_OFFLINE_SIGNING:
    raise RuntimeError(
        "Offline signing must remain enabled."
    )

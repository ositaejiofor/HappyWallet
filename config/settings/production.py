"""
HappyWallet Production Settings.

Production-only configuration.

Base configuration is inherited from:
config.settings.base
"""

import os

from dotenv import load_dotenv

from .base import *  # noqa: F403,F401

# ============================================================================

# ENVIRONMENT

# ============================================================================

ENVIRONMENT = "production"

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

# ============================================================================

# SECURITY

# ============================================================================

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "DJANGO_SECRET_KEY must be configured in production."
    )

DEBUG = False

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
)

# ============================================================================

# DATABASE

# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    try:
        import dj_database_url

        DATABASES = {
            "default": dj_database_url.parse(
                DATABASE_URL,
                conn_max_age=600,
                conn_health_checks=True,
                ssl_require=True,
            )
        }

    except ImportError as exc:
        raise RuntimeError(
            "dj-database-url is required when DATABASE_URL is configured."
        ) from exc

else:
    DATABASES = {
        "default": {
            "ENGINE": os.getenv(
                "DB_ENGINE",
                "django.db.backends.postgresql",
            ),
            "NAME": os.getenv("DB_NAME", ""),
            "USER": os.getenv("DB_USER", ""),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", ""),
            "PORT": os.getenv("DB_PORT", "5432"),
            "CONN_MAX_AGE": 600,
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": {
                "sslmode": os.getenv(
                    "DB_SSLMODE",
                    "require",
                ),
            },
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

# HTTPS / SECURITY HEADERS

# ============================================================================

SECURE_SSL_REDIRECT = True

SECURE_PROXY_SSL_HEADER = (
"HTTP_X_FORWARDED_PROTO",
"https",
)

SESSION_COOKIE_SECURE = True

CSRF_COOKIE_SECURE = True

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"

SECURE_HSTS_SECONDS = 31536000

SECURE_HSTS_INCLUDE_SUBDOMAINS = True

SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_REFERRER_POLICY = "same-origin"

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# ============================================================================

# CSRF TRUSTED ORIGINS

# ============================================================================

CSRF_TRUSTED_ORIGINS = env_list(
"DJANGO_CSRF_TRUSTED_ORIGINS",
)

# ============================================================================

# EMAIL

# ============================================================================

EMAIL_BACKEND = (
"django.core.mail.backends.smtp.EmailBackend"
)

EMAIL_HOST = os.getenv(
"EMAIL_HOST",
"",
)

EMAIL_PORT = int(
os.getenv(
"EMAIL_PORT",
"587",
)
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
)

EMAIL_HOST_PASSWORD = os.getenv(
"EMAIL_HOST_PASSWORD",
"",
)

DEFAULT_FROM_EMAIL = os.getenv(
"DEFAULT_FROM_EMAIL",
"[no-reply@happywallet.local](mailto:no-reply@happywallet.local)",
)

# ============================================================================

# CELERY

# ============================================================================

CELERY_BROKER_URL = os.getenv(
"CELERY_BROKER_URL",
)

CELERY_RESULT_BACKEND = os.getenv(
"CELERY_RESULT_BACKEND",
)

if not CELERY_BROKER_URL:
    raise RuntimeError(
        "CELERY_BROKER_URL must be configured in production."
    )

# ============================================================================

# CHANNELS

# ============================================================================

REDIS_URL = os.getenv(
"REDIS_URL",
CELERY_BROKER_URL,
)

CHANNEL_LAYERS = {
"default": {
"BACKEND": "channels_redis.core.RedisChannelLayer",
"CONFIG": {
"hosts": [
REDIS_URL,
],
},
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

# BLOCKCHAIN NETWORKS

# ============================================================================

SUPPORTED_BLOCKCHAIN_NETWORKS = {
"ethereum",
"bitcoin",
"tron",
}

# ============================================================================

# WALLET / TRANSACTION SECURITY

# ============================================================================

WALLET_ENVIRONMENT = "production"

WALLET_REQUIRE_CONFIRMATION = env_bool(
"WALLET_REQUIRE_CONFIRMATION",
True,
)

# Explicit opt-in only.

#

# The default is False so deploying the application does NOT

# automatically authorize blockchain broadcasting.

WALLET_ALLOW_BROADCAST = env_bool(
"WALLET_ALLOW_BROADCAST",
False,
)

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

# LOGGING

# ============================================================================

LOGGING["handlers"]["console"]["level"] = "INFO"  # noqa: F405

LOGGING["loggers"]["django"]["level"] = "INFO"  # noqa: F405

LOGGING["loggers"]["apps"]["level"] = "INFO"  # noqa: F405

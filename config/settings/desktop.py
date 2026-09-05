"""
HappyWallet Desktop Settings.

Desktop mode is intended for the normal local/desktop
HappyWallet application environment.

This configuration inherits the development configuration
and adds desktop-specific behavior.

Desktop mode is NOT production mode.

The desktop application may use:

    http://127.0.0.1:9000/

and therefore does not force HTTPS-only settings.
"""

from .development import *  # noqa: F403,F401


# ============================================================================
# ENVIRONMENT
# ============================================================================

ENVIRONMENT = "desktop"

APP_MODE = "desktop"


# ============================================================================
# DEBUG / DEVELOPMENT
# ============================================================================

DEBUG = True

DEVELOPMENT_SERVER = True


# ============================================================================
# HOSTS
# ============================================================================

ALLOWED_HOSTS = [
    "127.0.0.1",
    "localhost",
]


# ============================================================================
# CSRF TRUSTED ORIGINS
# ============================================================================

CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:9000",
    "http://localhost:9000",
]


# ============================================================================
# DESKTOP HTTP SECURITY
# ============================================================================

# The desktop development server runs over HTTP.
# Do not enable these settings here.

SECURE_SSL_REDIRECT = False

SESSION_COOKIE_SECURE = False

CSRF_COOKIE_SECURE = False

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"


# ============================================================================
# WALLET MODE
# ============================================================================

WALLET_OFFLINE_MODE = False

USB_WALLET_ENABLED = True


# ============================================================================
# MARKET / BLOCKCHAIN ACCESS
# ============================================================================

MARKET_DATA_ENABLED = True

BLOCKCHAIN_ACCESS_ENABLED = True


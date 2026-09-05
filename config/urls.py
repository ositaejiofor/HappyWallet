from __future__ import annotations

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    # ========================================================================
    # ADMINISTRATION
    # ========================================================================

    path(
        "admin/",
        admin.site.urls,
    ),

    # ========================================================================
    # DASHBOARD
    # ========================================================================

    path(
        "",
        include("apps.dashboard.urls"),
    ),

    # ========================================================================
    # ACCOUNTS
    # ========================================================================

    path(
        "accounts/",
        include("apps.accounts.urls"),
    ),

    # ========================================================================
    # WALLET
    # ========================================================================

    path(
        "wallet/",
        include("apps.wallet.urls"),
    ),

    # ========================================================================
    # PORTFOLIO
    # ========================================================================

    path(
        "portfolio/",
        include("apps.portfolio.urls"),
    ),

    # ========================================================================
    # TRANSACTIONS
    # ========================================================================

    path(
        "transactions/",
        include("apps.transaction.urls"),
    ),

    # ========================================================================
    # SECURITY
    # ========================================================================

    path(
        "security/",
        include("apps.security.urls"),
    ),
    
    
        # ========================================================================
    # TOKEN SCANNER
    # ========================================================================

    path(
        "token-scanner/",
        include("apps.token_scanner.urls"),
    ),
    
    path(
        "market/",
          include("apps.market.urls"),
    ),
    
    
    path(
        "trading/",
          include("apps.trading.urls"),
    ),
]


# ============================================================================
# DEVELOPMENT MEDIA FILES
# ============================================================================

if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )
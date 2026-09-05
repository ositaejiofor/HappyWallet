"""
HappyWallet wallet URL configuration.

This module defines HTTP routes for wallet operations.

Security boundary
-----------------
URL routing contains no wallet cryptographic logic and never handles
wallet secrets directly. Sensitive operations are delegated to the
corresponding wallet application services through the views.
"""

from __future__ import annotations

from django.urls import path

from . import views


app_name = "wallet"


urlpatterns = [
    # ========================================================================
    # WALLET DASHBOARD
    # ========================================================================

    path(
        "",
        views.wallet_home,
        name="home",
    ),

    # ========================================================================
    # WALLET CREATION
    # ========================================================================

    path(
        "create/",
        views.create_wallet,
        name="create",
    ),

    # ========================================================================
    # WALLET UNLOCK
    # ========================================================================

    path(
        "unlock/",
        views.unlock_wallet,
        name="unlock",
    ),
]

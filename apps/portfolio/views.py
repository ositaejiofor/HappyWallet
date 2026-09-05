# apps/portfolio/views.py

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from apps.wallet.models import Wallet
from apps.wallet.services.wallet_balance import (
    WalletDashboardBalance,
    get_wallet_dashboard_balance,
)


# ============================================================================
# LOGGER
# ============================================================================

logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

APP_NAME = "HappyWallet"
PORTFOLIO_TEMPLATE = "portfolio/home.html"


# ============================================================================
# PORTFOLIO
# ============================================================================

@login_required
def portfolio(request: HttpRequest) -> HttpResponse:
    """
    Render the authenticated user's portfolio.

    This view is strictly read-only.

    It does not:
        - access private keys
        - access wallet secrets
        - sign transactions
        - broadcast transactions
        - create transactions
        - modify wallet records
    """

    wallet = _get_user_wallet(user=request.user)

    balance = _get_wallet_balance(wallet=wallet)

    context = _build_context(
        wallet=wallet,
        balance=balance,
    )

    return render(
        request,
        PORTFOLIO_TEMPLATE,
        context,
    )


# ============================================================================
# WALLET LOOKUP
# ============================================================================

def _get_user_wallet(
    *,
    user: Any,
) -> Wallet | None:
    """
    Return the authenticated user's newest wallet.

    The newest wallet is determined by:
        1. created_at descending
        2. id descending as a deterministic fallback
    """

    return (
        Wallet.objects
        .select_related("network")
        .filter(user=user)
        .order_by(
            "-created_at",
            "-id",
        )
        .first()
    )


# ============================================================================
# BALANCE
# ============================================================================

def _get_wallet_balance(
    *,
    wallet: Wallet | None,
) -> WalletDashboardBalance | None:
    """
    Retrieve the authoritative wallet balance used by the dashboard.

    Portfolio is read-only and delegates blockchain access to the existing
    wallet balance service. No private-key or transaction functionality is
    accessed here.
    """

    if wallet is None:
        return None

    try:
        return get_wallet_dashboard_balance(
            wallet=wallet,
        )
    except Exception:
        logger.exception(
            "Unable to retrieve portfolio balance for wallet %s.",
            wallet.pk,
        )
        return None


# ============================================================================
# CONTEXT
# ============================================================================

def _build_context(
    *,
    wallet: Wallet | None,
    balance: WalletDashboardBalance | None,
) -> dict[str, Any]:
    """
    Build the context required by the portfolio template.
    """

    return {
        "app_name": APP_NAME,
        "wallet": wallet,
        "balance": balance,
        "blockchain_available": balance is not None,
    }
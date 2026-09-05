# apps/dashboard/views.py

"""
HappyWallet Dashboard Views.

The dashboard is intentionally lightweight and read-only.

Responsibilities
----------------
- Resolve the authenticated user's wallet.
- Resolve the current public blockchain balance.
- Prepare dashboard presentation data.
- Never perform transaction-history RPC scans synchronously.

Transaction history is intentionally excluded from the dashboard request path
because Ethereum historical transaction discovery may require multiple RPC
requests and retries. The dedicated transaction application owns that work.

Security boundary
-----------------
This module MUST NEVER:

- access private keys
- access recovery phrases
- access mnemonics
- decrypt wallet secrets
- sign transactions
- create transactions
- broadcast transactions
- modify wallet records
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from apps.transaction.services.history import (
    TransactionHistory,
    WalletTransaction,
)
from apps.wallet.models import Wallet
from apps.wallet.services.wallet_balance import (
    WalletDashboardBalance,
    get_wallet_dashboard_balance,
)


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

DASHBOARD_TEMPLATE = "dashboard/index.html"
APP_NAME = "HappyWallet"

RECENT_TRANSACTION_LIMIT = 5


# ============================================================================
# DASHBOARD
# ============================================================================


@login_required
def dashboard(
    request: HttpRequest,
) -> HttpResponse:
    """
    Render the authenticated user's HappyWallet dashboard.

    The dashboard performs only the operations required to display the
    current wallet state.

    Important performance rule
    --------------------------
    Transaction history is NOT retrieved during this request.

    Ethereum transaction history requires a bounded block scan and may
    result in many RPC requests. Performing that operation here can make
    the entire dashboard appear to hang when the provider is slow or
    temporarily unavailable.

    The dedicated transaction page is responsible for transaction history.

    Security
    --------
    This view is strictly read-only and never handles wallet secrets.
    """

    wallet = _get_user_wallet(
        user=request.user,
    )

    balance = _get_wallet_balance(
        wallet=wallet,
    )

    # ------------------------------------------------------------------------
    # IMPORTANT:
    #
    # Do NOT call get_wallet_transaction_history() here.
    #
    # The dashboard must remain responsive even when the transaction-history
    # provider is slow, unavailable, or experiencing transport failures.
    # ------------------------------------------------------------------------

    history = _unavailable_transaction_history()

    context = _build_context(
        wallet=wallet,
        balance=balance,
        history=history,
    )

    return render(
        request,
        DASHBOARD_TEMPLATE,
        context,
    )


# ============================================================================
# WALLET
# ============================================================================


def _get_user_wallet(
    *,
    user: Any,
) -> Wallet | None:
    """
    Return the authenticated user's newest wallet.

    The network relationship is eagerly loaded because the dashboard
    displays network metadata.

    The queryset is explicitly restricted to the authenticated user.
    """

    return (
        Wallet.objects
        .select_related("network")
        .filter(
            user=user,
        )
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
    Retrieve the wallet's current public blockchain balance.

    All blockchain communication is delegated to the wallet balance service.

    A provider/configuration failure must never cause the dashboard to
    return HTTP 500.
    """

    if wallet is None:
        return None

    try:
        return get_wallet_dashboard_balance(
            wallet=wallet,
        )

    except (ValueError, RuntimeError) as exc:
        logger.warning(
            "Wallet balance unavailable for wallet %s: %s",
            wallet.pk,
            exc,
        )

        return None

    except Exception:
        logger.exception(
            "Unexpected wallet balance failure for wallet %s.",
            wallet.pk,
        )

        return None


# ============================================================================
# TRANSACTION HISTORY
# ============================================================================


def _unavailable_transaction_history() -> TransactionHistory:
    """
    Return the dashboard's transaction-history state.

    The dashboard intentionally does not query the blockchain for historical
    transactions.

    ``available=False`` is important because:

        available=False
            History was not requested by the dashboard.

        available=True + transactions=()
            History was actually queried and no transactions were found.

    Therefore the dashboard must not represent its intentionally omitted
    history as an empty successful history result.
    """

    return TransactionHistory(
        transactions=(),
        available=False,
    )


# ============================================================================
# CONTEXT
# ============================================================================


def _build_context(
    *,
    wallet: Wallet | None,
    balance: WalletDashboardBalance | None,
    history: TransactionHistory,
) -> dict[str, Any]:
    """
    Build the complete dashboard template context.

    The view does not calculate blockchain balances.

    ``WalletDashboardBalance`` remains the authoritative source for:

    - native balance
    - token balances
    - asset count
    - blockchain availability
    - network metadata
    """

    wallet_exists = wallet is not None

    # ------------------------------------------------------------------------
    # BLOCKCHAIN
    # ------------------------------------------------------------------------

    blockchain_available = bool(
        balance is not None
        and balance.blockchain_available
    )

    # ------------------------------------------------------------------------
    # BALANCE
    # ------------------------------------------------------------------------

    native_balance = (
        balance.native_balance
        if balance is not None
        else None
    )

    token_balances = (
        balance.tokens
        if balance is not None
        else ()
    )

    wallet_asset_count = (
        balance.asset_count
        if balance is not None
        else 0
    )

    # ------------------------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------------------------

    network = getattr(
        wallet,
        "network",
        None,
    )

    if balance is not None:
        network_name = (
            balance.network
            or getattr(
                network,
                "name",
                None,
            )
            or "Unknown Network"
        )

        network_symbol = (
            balance.native_symbol
            or balance.network_symbol
            or getattr(
                network,
                "symbol",
                None,
            )
            or "—"
        )

    else:
        network_name = (
            getattr(
                network,
                "name",
                None,
            )
            or "Unknown Network"
        )

        network_symbol = (
            getattr(
                network,
                "symbol",
                None,
            )
            or "—"
        )

    # ------------------------------------------------------------------------
    # RECENT TRANSACTIONS
    # ------------------------------------------------------------------------

    recent_transactions: tuple[
        WalletTransaction,
        ...
    ] = history.transactions[
        :RECENT_TRANSACTION_LIMIT
    ]

    # ------------------------------------------------------------------------
    # CONTEXT
    # ------------------------------------------------------------------------

    return {
        # Application
        "app_name": APP_NAME,

        # Wallet
        "wallet": wallet,
        "wallet_exists": wallet_exists,

        # Network
        "network": network,
        "network_name": network_name,
        "network_symbol": network_symbol,

        # Blockchain
        "balance": balance,
        "native_balance": native_balance,
        "blockchain_available": blockchain_available,

        # Assets
        "token_balances": token_balances,
        "wallet_asset_count": wallet_asset_count,

        # Transactions
        "recent_transactions": recent_transactions,
        "recent_transaction_count": len(
            recent_transactions,
        ),
        "transaction_history_available": history.available,
    }


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================


__all__ = [
    "dashboard",
]

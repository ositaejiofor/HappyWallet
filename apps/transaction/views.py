"""
HappyWallet Transaction Views.

Presentation boundary for authenticated, read-only wallet transaction
history.

Security boundary
-----------------

These views MUST NEVER:

    - access private keys;
    - access mnemonics or recovery phrases;
    - access wallet seeds;
    - decrypt wallet secrets;
    - access signing material;
    - sign transactions;
    - broadcast transactions;
    - create blockchain transactions;
    - modify wallet records;
    - persist provider transaction history.

Blockchain transaction-history retrieval belongs exclusively to the
transaction service layer.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render

from apps.transaction.services.history import (
    TransactionHistory,
    get_wallet_transaction_history,
)
from apps.wallet.models import Wallet


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

TRANSACTION_TEMPLATE = "transaction/index.html"
APP_NAME = "HappyWallet"


# ============================================================================
# PUBLIC VIEWS
# ============================================================================


@login_required
def transaction_list(
    request: HttpRequest,
) -> HttpResponse:
    """
    Render the authenticated user's public transaction history.

    Authentication is enforced by ``login_required``.

    The view only resolves the authenticated user's wallet and delegates
    public blockchain history retrieval to the transaction service.
    """

    wallets = tuple(_get_user_wallets(user=request.user))
    wallet = _get_user_wallet(
        user=request.user,
        wallet_id=request.GET.get("wallet"),
    )

    history = _resolve_transaction_history(
        wallet=wallet,
    )

    context = _build_context(
        wallet=wallet,
        history=history,
        wallet_options=wallets,
    )

    return render(
        request,
        TRANSACTION_TEMPLATE,
        context,
    )


# ============================================================================
# WALLET RESOLUTION
# ============================================================================


def _get_user_wallets(*, user: Any):
    """Return the authenticated user's wallets in stable default order."""

    if user is None:
        return Wallet.objects.none()

    return (
        Wallet.objects
        .select_related("network")
        .filter(user=user)
        .order_by("-created_at", "-id")
    )


def _get_user_wallet(
    *,
    user: Any,
    wallet_id: str | None = None,
) -> Wallet | None:
    """
    Return the authenticated user's newest wallet.

    Ownership is enforced directly by the queryset.

    The wallet's blockchain network is eagerly loaded because the
    transaction template may display public network metadata.
    """

    wallets = _get_user_wallets(user=user)

    if not wallet_id:
        return wallets.first()

    try:
        selected_id = UUID(str(wallet_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise Http404("Wallet not found.") from exc

    wallet = wallets.filter(pk=selected_id).first()

    if wallet is None:
        raise Http404("Wallet not found.")

    return wallet


# ============================================================================
# TRANSACTION HISTORY
# ============================================================================


def _resolve_transaction_history(
    *,
    wallet: Wallet | None,
) -> TransactionHistory:
    """
    Resolve public transaction history through the service layer.

    Provider failures are converted into the canonical unavailable
    application result.

    No blockchain-provider logic belongs in this view.
    """

    if wallet is None:
        return _unavailable_history(
            reason="wallet_missing",
        )

    try:
        history = get_wallet_transaction_history(
            wallet=wallet,
        )

    except (ValueError, RuntimeError) as exc:
        logger.warning(
            "Transaction history unavailable for wallet %s: %s",
            wallet.pk,
            type(exc).__name__,
        )

        return _unavailable_history(
            reason="provider_or_validation_failure",
        )

    except Exception:
        logger.exception(
            "Unexpected transaction history failure for wallet %s.",
            wallet.pk,
        )

        return _unavailable_history(
            reason="unexpected_failure",
        )

    if not isinstance(
        history,
        TransactionHistory,
    ):
        logger.error(
            "Transaction history service returned an invalid result "
            "for wallet %s.",
            wallet.pk,
        )

        return _unavailable_history(
            reason="invalid_service_result",
        )

    return history


# ============================================================================
# SAFE FALLBACK
# ============================================================================


def _unavailable_history(
    *,
    reason: str,
) -> TransactionHistory:
    """
    Return the canonical unavailable transaction-history result.

    ``reason`` is deliberately used only for server-side diagnostics.
    It is never exposed to the template or user.
    """

    logger.debug(
        "Transaction history unavailable: %s",
        reason,
    )

    return TransactionHistory(
        transactions=(),
        available=False,
    )


# ============================================================================
# TEMPLATE CONTEXT
# ============================================================================


def _build_context(
    *,
    wallet: Wallet | None,
    history: TransactionHistory,
    wallet_options: tuple[Wallet, ...] = (),
) -> dict[str, Any]:
    """
    Build the presentation context for the transaction page.

    Only application-level transaction DTOs are passed to the template.
    Provider-specific objects never reach presentation code.
    """

    transactions = history.transactions

    return {
        "app_name": APP_NAME,
        "wallet": wallet,
        "wallet_options": wallet_options,
        "selected_wallet_id": str(wallet.pk) if wallet else "",
        "transactions": transactions,
        "transaction_count": len(transactions),
        "transaction_history_available": history.available,
    }


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================

__all__ = [
    "transaction_list",
]

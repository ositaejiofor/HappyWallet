"""
HappyWallet trading views.

This module handles the trading dashboard and order workflow.

Trading remains deliberately separated from blockchain signing:

    BlockchainNetwork / Asset
        -> supported blockchain infrastructure

    MarketAsset / TradingPair
        -> market and trading instruments

    TradingAccount / TradingBalance / Order / Trade
        -> trading state

These views never access private keys, wallet secrets, signing material,
or blockchain transaction broadcasting.
"""

from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404, redirect, render

from apps.blockchain.models import Asset, BlockchainNetwork

from .models import Order, TradingAccount, TradingPair
from .services import (
    KrakenOrderReconciliationService,
    KrakenReconciliationError,
    LiveExecutionError,
    LiveExecutionService,
    OrderService,
    PaperTradingEngine,
)


LIVE_CONFIRMATION_PHRASE = "PLACE LIVE ORDER"


def _live_trading_status(account):
    enabled = bool(
        getattr(settings, "KRAKEN_LIVE_TRADING_ENABLED", False)
    )
    configured = bool(
        getattr(settings, "KRAKEN_API_KEY", "")
        and getattr(settings, "KRAKEN_API_SECRET", "")
    )
    return {
        "account_is_live": account.mode == TradingAccount.Mode.LIVE,
        "enabled": enabled,
        "configured": configured,
        "ready": (
            account.mode == TradingAccount.Mode.LIVE
            and account.is_active
            and enabled
            and configured
        ),
    }


def _get_trading_account(user):
    """
    Return the user's trading account, creating it when necessary.
    """
    account, _ = TradingAccount.objects.get_or_create(
        user=user,
    )
    return account


def _get_supported_networks():
    """
    Return active blockchain networks with their active assets.

    Active assets are attached to each network as ``supported_assets``.
    This avoids changing the existing ``assets`` relationship and prevents
    inactive assets from appearing in the trading dashboard.
    """
    supported_assets = (
        Asset.objects
        .filter(is_active=True)
        .order_by("symbol")
    )

    return (
        BlockchainNetwork.objects
        .filter(is_active=True)
        .prefetch_related(
            Prefetch(
                "assets",
                queryset=supported_assets,
                to_attr="supported_assets",
            )
        )
        .order_by("name")
    )


def _get_supported_assets():
    """
    Return active blockchain assets belonging to active networks.
    """
    return (
        Asset.objects
        .filter(
            is_active=True,
            network__is_active=True,
        )
        .select_related("network")
        .order_by(
            "network__name",
            "symbol",
        )
    )


def _get_active_trading_pairs():
    """
    Return active market trading pairs.
    """
    return (
        TradingPair.objects
        .filter(is_active=True)
        .select_related(
            "base_asset",
            "quote_asset",
        )
        .order_by("symbol")
    )


def _get_recent_orders(account, limit=10):
    """
    Return the user's most recent trading orders.
    """
    return (
        Order.objects
        .filter(account=account)
        .select_related(
            "pair__base_asset",
            "pair__quote_asset",
        )
        .order_by("-created_at")[:limit]
    )


def _get_trading_balances(account):
    """
    Return the trading account's balances ordered by asset symbol.

    These are trading balances backed by ``market.MarketAsset``.
    They are intentionally separate from blockchain wallet balances.
    """
    return (
        account.balances
        .select_related("asset")
        .order_by("asset__symbol")
    )


@login_required
def trading_home(request):
    """
    Display the main HappyWallet trading dashboard.
    """
    account = _get_trading_account(request.user)
    live_status = _live_trading_status(account)

    return render(
        request,
        "trading/home.html",
        {
            "account": account,
            "networks": _get_supported_networks(),
            "assets": _get_supported_assets(),
            "pairs": _get_active_trading_pairs(),
            "orders": _get_recent_orders(account),
            "balances": _get_trading_balances(account),
            "live_status": live_status,
        },
    )


@login_required
def order_list(request):
    """
    Display all orders belonging to the authenticated user.
    """
    account = _get_trading_account(request.user)

    orders = (
        Order.objects
        .filter(account=account)
        .select_related(
            "pair__base_asset",
            "pair__quote_asset",
        )
        .order_by("-created_at")
    )

    return render(
        request,
        "trading/orders.html",
        {
            "account": account,
            "orders": orders,
        },
    )


@login_required
def create_order(request):
    """
    Create a new trading order.

    Orders are created as PENDING and are not automatically executed.
    """
    if request.method != "POST":
        return redirect("trading:home")

    account = _get_trading_account(request.user)

    pair_id = request.POST.get("pair", "").strip()
    side = request.POST.get("side", "").strip()
    order_type = request.POST.get("order_type", "").strip()

    quantity_raw = request.POST.get(
        "quantity",
        "",
    ).strip()

    limit_price_raw = request.POST.get(
        "limit_price",
        "",
    ).strip()

    if not pair_id:
        messages.error(
            request,
            "Please select a trading pair.",
        )
        return redirect("trading:home")

    if not quantity_raw:
        messages.error(
            request,
            "Order quantity is required.",
        )
        return redirect("trading:home")

    pair = get_object_or_404(
        TradingPair,
        pk=pair_id,
        is_active=True,
    )

    try:
        quantity = Decimal(quantity_raw)

        limit_price = (
            Decimal(limit_price_raw)
            if limit_price_raw
            else None
        )

        order = OrderService.create_order(
            account=account,
            pair=pair,
            side=side,
            order_type=order_type,
            quantity=quantity,
            limit_price=limit_price,
        )

    except (InvalidOperation, TypeError):
        messages.error(
            request,
            "Please enter valid numeric values.",
        )
        return redirect("trading:home")

    except ValidationError as exc:
        messages.error(
            request,
            str(exc),
        )
        return redirect("trading:home")

    messages.success(
        request,
        (
            f"{order.side.title()} order created for "
            f"{order.quantity} "
            f"{order.pair.base_asset.symbol.upper()}."
        ),
    )

    return redirect(
        "trading:order_detail",
        order_id=order.id,
    )


@login_required
def order_detail(request, order_id):
    """
    Display one trading order and its executions.
    """
    account = _get_trading_account(request.user)

    order = get_object_or_404(
        Order.objects.select_related(
            "pair__base_asset",
            "pair__quote_asset",
        ),
        pk=order_id,
        account=account,
    )

    trades = (
        order.trades
        .select_related("fee_asset")
        .order_by("-executed_at")
    )

    return render(
        request,
        "trading/order_detail.html",
        {
            "account": account,
            "order": order,
            "trades": trades,
            "live_status": _live_trading_status(account),
            "live_confirmation_phrase": LIVE_CONFIRMATION_PHRASE,
        },
    )


@login_required
def cancel_order(request, order_id):
    """
    Cancel an outstanding trading order.

    Cancellation is POST-only.
    """
    if request.method != "POST":
        return redirect(
            "trading:order_detail",
            order_id=order_id,
        )

    account = _get_trading_account(request.user)

    order = get_object_or_404(
        Order,
        pk=order_id,
        account=account,
    )

    try:
        OrderService.cancel_order(
            account=account,
            order=order,
        )

    except ValidationError as exc:
        messages.error(
            request,
            str(exc),
        )

    else:
        messages.success(
            request,
            "Trading order cancelled.",
        )

    return redirect(
        "trading:order_detail",
        order_id=order.id,
    )


@login_required
def execute_paper_order(request, order_id):
    """
    Execute a trading order through the paper-trading engine.

    The paper engine does not:

        - access private keys
        - access wallet secrets
        - sign blockchain transactions
        - broadcast blockchain transactions
    """
    if request.method != "POST":
        return redirect(
            "trading:order_detail",
            order_id=order_id,
        )

    account = _get_trading_account(request.user)

    order = get_object_or_404(
        Order,
        pk=order_id,
        account=account,
    )

    if account.mode != TradingAccount.Mode.PAPER:
        messages.error(request, "Live orders cannot use the paper engine.")
        return redirect("trading:order_detail", order_id=order.id)

    try:
        trade = PaperTradingEngine.execute(order)

    except ValidationError as exc:
        messages.error(
            request,
            str(exc),
        )

    else:
        messages.success(
            request,
            (
                "Paper trade executed: "
                f"{trade.quantity} "
                f"{order.pair.base_asset.symbol.upper()} "
                f"@ {trade.price}"
            ),
        )

    return redirect(
        "trading:order_detail",
        order_id=order.id,
    )


@login_required
def execute_live_order(request, order_id):
    """Submit one explicitly confirmed live order through the guarded boundary."""
    if request.method != "POST":
        return redirect("trading:order_detail", order_id=order_id)

    account = _get_trading_account(request.user)
    order = get_object_or_404(Order, pk=order_id, account=account)

    acknowledged = request.POST.get("acknowledge_live_risk") == "yes"
    phrase = request.POST.get("confirmation_phrase", "").strip()

    if not acknowledged or phrase != LIVE_CONFIRMATION_PHRASE:
        messages.error(
            request,
            "Live order confirmation was not completed. Nothing was submitted.",
        )
        return redirect("trading:order_detail", order_id=order.id)

    try:
        submitted = LiveExecutionService().execute(
            account=account,
            order=order,
            confirmed=True,
        )
    except (ValidationError, LiveExecutionError) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(
            request,
            "Kraken accepted the order for processing. Acceptance is not a fill.",
        )
        order = submitted

    return redirect("trading:order_detail", order_id=order.id)


@login_required
def reconcile_live_order(request, order_id):
    """Perform read-only Kraken reconciliation for an uncertain live order."""
    if request.method != "POST":
        return redirect("trading:order_detail", order_id=order_id)

    account = _get_trading_account(request.user)
    order = get_object_or_404(Order, pk=order_id, account=account)

    try:
        KrakenOrderReconciliationService().reconcile(
            account=account,
            order=order,
        )
    except (ValidationError, KrakenReconciliationError) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Kraken order status was reconciled.")

    return redirect("trading:order_detail", order_id=order.id)

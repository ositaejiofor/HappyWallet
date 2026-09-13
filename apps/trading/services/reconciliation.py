"""
HappyWallet Kraken live-order reconciliation.

This module performs read-only reconciliation of orders whose exchange
submission outcome is uncertain.

Safety rules
------------
- Never submits an order.
- Never retries AddOrder.
- Never signs blockchain transactions.
- Never accesses wallet private keys or seed phrases.
- A missing Kraken order is NOT treated as proof that submission failed.
- UNKNOWN orders remain UNKNOWN until a reliable exchange result exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import Order, TradingAccount
from .kraken import KrakenAPIError, KrakenAdapter


class KrakenReconciliationError(Exception):
    """Raised when Kraken reconciliation cannot be completed safely."""


@dataclass(frozen=True)
class KrakenOrderMatch:
    """
    Normalized Kraken order discovered during reconciliation.
    """

    exchange_order_id: str
    data: dict
    source: str


class KrakenOrderReconciliationService:
    """
    Reconcile uncertain HappyWallet orders against Kraken.

    This service is intentionally read-only with respect to Kraken.
    """

    RECONCILABLE_STATUSES = {
        Order.Status.SUBMITTING,
        Order.Status.UNKNOWN,
    }

    def __init__(self, *, adapter=None):
        self.adapter = adapter or KrakenAdapter()

    @staticmethod
    def _ensure_account_is_live(*, account):
        if not account.is_active:
            raise ValidationError(
                "Trading account is inactive."
            )

        if account.mode != TradingAccount.Mode.LIVE:
            raise ValidationError(
                "Reconciliation requires a live trading account."
            )

    @classmethod
    def _ensure_order_can_reconcile(
        cls,
        *,
        account,
        order,
    ):
        if order.account_id != account.id:
            raise ValidationError(
                "This order does not belong to the trading account."
            )

        if order.status not in cls.RECONCILABLE_STATUSES:
            raise ValidationError(
                "This order does not require reconciliation."
            )

        if not str(
            order.exchange_client_order_id or ""
        ).strip():
            raise ValidationError(
                "Order has no exchange client order ID."
            )

    @staticmethod
    def _extract_orders(result, key):
        """
        Extract an order mapping from a Kraken response.

        Kraken's OpenOrders/ClosedOrders result normally contains:

            {"open": {...}}

        or:

            {"closed": {...}}
        """

        if not isinstance(result, dict):
            raise KrakenReconciliationError(
                "Kraken returned an invalid reconciliation response."
            )

        orders = result.get(key)

        if orders is None:
            return {}

        if not isinstance(orders, dict):
            raise KrakenReconciliationError(
                "Kraken returned an invalid reconciliation order list."
            )

        return orders

    @staticmethod
    def _client_order_id(order_data):
        """
        Return Kraken's client order ID from an order payload.

        Keep the extraction conservative and explicit.
        """

        if not isinstance(order_data, dict):
            return ""

        value = order_data.get("cl_ord_id")

        if value is None:
            return ""

        return str(value).strip()

    @classmethod
    def _find_match(
        cls,
        *,
        orders,
        exchange_client_order_id,
        source,
    ):
        matches = []

        for exchange_order_id, order_data in orders.items():
            if not isinstance(order_data, dict):
                continue

            candidate = cls._client_order_id(
                order_data
            )

            if candidate != exchange_client_order_id:
                continue

            matches.append(
                KrakenOrderMatch(
                    exchange_order_id=str(
                        exchange_order_id
                    ).strip(),
                    data=order_data,
                    source=source,
                )
            )

        if len(matches) > 1:
            raise KrakenReconciliationError(
                "Kraken returned multiple orders for the "
                "same exchange client order ID."
            )

        if matches:
            return matches[0]

        return None

    @staticmethod
    def _closed_status(order_data):
        status = str(
            order_data.get("status", "")
        ).strip().lower()

        if status == "closed":
            return Order.Status.FILLED

        if status in {
            "canceled",
            "cancelled",
            "expired",
        }:
            return Order.Status.CANCELLED

        return None

    def _lookup(self, *, exchange_client_order_id):
        """
        Search Kraken open orders first, then closed orders.

        No AddOrder call is made here.
        """

        try:
            open_result = self.adapter.get_open_orders(
                trades=False
            )

            open_orders = self._extract_orders(
                open_result,
                "open",
            )

            match = self._find_match(
                orders=open_orders,
                exchange_client_order_id=(
                    exchange_client_order_id
                ),
                source="open",
            )

            if match is not None:
                return match

            closed_result = self.adapter.get_closed_orders(
                trades=False
            )

            closed_orders = self._extract_orders(
                closed_result,
                "closed",
            )

            return self._find_match(
                orders=closed_orders,
                exchange_client_order_id=(
                    exchange_client_order_id
                ),
                source="closed",
            )

        except KrakenReconciliationError:
            raise

        except KrakenAPIError as exc:
            raise KrakenReconciliationError(
                "Kraken reconciliation request failed."
            ) from exc

    def reconcile(
        self,
        *,
        account: TradingAccount,
        order: Order,
    ):
        """
        Reconcile one uncertain order.

        Not finding the order leaves it UNKNOWN. It does NOT make the
        order eligible for automatic resubmission.
        """

        self._ensure_account_is_live(
            account=account
        )

        # Read the latest local state before making read-only Kraken
        # requests. Do not hold a DB transaction across network I/O.
        current_order = (
            Order.objects
            .select_related("account")
            .get(pk=order.pk)
        )

        self._ensure_order_can_reconcile(
            account=account,
            order=current_order,
        )

        exchange_client_order_id = (
            current_order.exchange_client_order_id
        )

        match = self._lookup(
            exchange_client_order_id=(
                exchange_client_order_id
            )
        )

        # Kraken did not provide enough evidence to establish what
        # happened. Preserve UNKNOWN rather than reopening submission.
        if match is None:
            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=current_order.pk)
                )

                self._ensure_order_can_reconcile(
                    account=account,
                    order=final_order,
                )

                final_order.status = (
                    Order.Status.UNKNOWN
                )

                final_order.submission_error = (
                    "Kraken reconciliation did not find a "
                    "matching order. Automatic resubmission "
                    "remains blocked."
                )

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            return final_order

        if not match.exchange_order_id:
            raise KrakenReconciliationError(
                "Kraken returned a matching order without "
                "an exchange order ID."
            )

        if match.source == "open":
            target_status = Order.Status.OPEN

        else:
            target_status = self._closed_status(
                match.data
            )

            if target_status is None:
                # An unrecognized exchange state must not be guessed.
                with transaction.atomic():
                    final_order = (
                        Order.objects
                        .select_for_update()
                        .get(pk=current_order.pk)
                    )

                    self._ensure_order_can_reconcile(
                        account=account,
                        order=final_order,
                    )

                    final_order.exchange_order_id = (
                        match.exchange_order_id
                    )
                    final_order.status = (
                        Order.Status.UNKNOWN
                    )
                    final_order.submission_error = (
                        "Kraken returned an unrecognized "
                        "closed-order status. Manual "
                        "reconciliation is required."
                    )

                    final_order.save(
                        update_fields=[
                            "exchange_order_id",
                            "status",
                            "submission_error",
                            "updated_at",
                        ]
                    )

                return final_order

        with transaction.atomic():
            final_order = (
                Order.objects
                .select_for_update()
                .get(pk=current_order.pk)
            )

            self._ensure_order_can_reconcile(
                account=account,
                order=final_order,
            )

            final_order.exchange_order_id = (
                match.exchange_order_id
            )
            final_order.status = target_status
            final_order.submission_error = ""

            final_order.save(
                update_fields=[
                    "exchange_order_id",
                    "status",
                    "submission_error",
                    "updated_at",
                ]
            )

        return final_order

"""
HappyWallet live trading execution boundary.

This service is the ONLY application-level boundary that should eventually
allow a Trading Order to reach a live exchange adapter.

Safety rules:
    - Paper accounts can never use this service.
    - Live trading must be explicitly enabled.
    - The order must belong to the supplied trading account.
    - Only valid, executable order states are accepted.
    - Kraken order submission remains disabled until the adapter and
      complete confirmation/risk boundary are implemented.
    - This service never accesses:
        * private keys
        * seed phrases
        * mnemonics
        * wallet secrets
        * blockchain signing material
"""


from django.conf import settings
from django.core.exceptions import ValidationError
import uuid

from decimal import Decimal, ROUND_DOWN

from django.db import transaction
from django.utils import timezone

from ..models import Order, TradingAccount
from .kraken import (
    KrakenAdapter,
    KrakenAPIError,
    KrakenConfigurationError,
    KrakenRejectedError,
    KrakenTransportError,
)
from .kraken_pairs import (
    KrakenPairError,
    KrakenPairService,
)
from .validation import validate_order


class LiveExecutionError(Exception):
    """Base exception for live execution failures."""


class LiveTradingDisabledError(LiveExecutionError):
    """Raised when live trading is not explicitly enabled."""


class LiveExecutionService:
    """
    Safety boundary for live exchange execution.

    This class deliberately does NOT submit real orders yet.

    The intended execution path is:

        Trading Order
            ↓
        LiveExecutionService
            ↓
        validation
            ↓
        confirmation/risk checks
            ↓
        KrakenAdapter
            ↓
        Kraken

    Until the complete safety boundary is implemented, live submission
    remains blocked.
    """

    def __init__(
        self,
        *,
        adapter=None,
        pair_service=None,
        confirmation_required=None,
    ):
        self.adapter = adapter or KrakenAdapter()

        self.pair_service = (
            pair_service
            or KrakenPairService(self.adapter)
        )

        if confirmation_required is None:
            confirmation_required = getattr(
                settings,
                "WALLET_REQUIRE_CONFIRMATION",
                True,
            )

        self.confirmation_required = bool(
            confirmation_required
        )

    @staticmethod
    def _ensure_account_is_live(
        *,
        account: TradingAccount,
    ):
        if not account.is_active:
            raise ValidationError(
                "Trading account is inactive."
            )

        if account.mode != TradingAccount.Mode.LIVE:
            raise ValidationError(
                "Live execution requires a live trading account."
            )

    @staticmethod
    def _ensure_order_belongs_to_account(
        *,
        account: TradingAccount,
        order: Order,
    ):
        if order.account_id != account.id:
            raise ValidationError(
                "This order does not belong to "
                "the trading account."
            )

    @staticmethod
    def _ensure_order_can_execute(
        *,
        order: Order,
    ):
        if order.status != Order.Status.PENDING:
            raise ValidationError(
                "This order cannot be submitted."
            )

    @staticmethod
    def _validate_order(
        *,
        order: Order,
    ):
        validate_order(
            pair=order.pair,
            side=order.side,
            order_type=order.order_type,
            quantity=order.quantity,
            limit_price=order.limit_price,
        )

    def _ensure_live_trading_enabled(self):
        """
        Enforce both application-level and adapter-level live guards.

        This method never enables live trading.
        """

        enabled = getattr(
            settings,
            "KRAKEN_LIVE_TRADING_ENABLED",
            False,
        )

        if not enabled:
            raise LiveTradingDisabledError(
                "Kraken live trading is disabled."
            )

        try:
            self.adapter.assert_live_trading_enabled()
        except KrakenConfigurationError as exc:
            raise LiveTradingDisabledError(
                str(exc)
            ) from exc

    @staticmethod
    def _quantize_decimal(value, precision):
        """
        Normalize a Decimal to Kraken precision without rounding up.
        """

        value = Decimal(str(value))

        quantum = Decimal("1").scaleb(
            -int(precision)
        )

        return value.quantize(
            quantum,
            rounding=ROUND_DOWN,
        )

    @staticmethod
    def _kraken_client_order_id(order):
        """
        Build a deterministic Kraken UUID from HappyWallet's
        unique client_order_id.

        Reusing the same HappyWallet order therefore produces
        the same Kraken client identifier.
        """

        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                (
                    "happywallet:kraken:"
                    f"{order.client_order_id}"
                ),
            )
        )

    @staticmethod
    def _decimal_string(value):
        """
        Convert Decimal to a non-scientific Kraken parameter string.
        """

        return format(
            value,
            "f",
        )

    def _prepare_order(
        self,
        *,
        order,
        pair_info,
    ):
        """
        Normalize order quantity/price against Kraken pair metadata.
        """

        quantity = self._quantize_decimal(
            order.quantity,
            pair_info.quantity_precision,
        )

        if quantity <= 0:
            raise ValidationError(
                "Order quantity becomes zero at Kraken precision."
            )

        if quantity < pair_info.minimum_order_quantity:
            raise ValidationError(
                "Order quantity is below Kraken minimum "
                f"of {pair_info.minimum_order_quantity}."
            )

        price = None

        if order.order_type == Order.OrderType.LIMIT:
            price = self._quantize_decimal(
                order.limit_price,
                pair_info.price_precision,
            )

            if price <= 0:
                raise ValidationError(
                    "Limit price becomes zero at Kraken precision."
                )

        return quantity, price

    def execute(
        self,
        *,
        account: TradingAccount,
        order: Order,
        confirmed=False,
    ):
        """
        Submit an existing PENDING order to Kraken.

        Safety model:

        1. Validate and persist SUBMITTING inside a short transaction.
        2. Commit before contacting Kraken.
        3. Submit to Kraken with a deterministic client order ID.
        4. Persist the exchange outcome inside another short transaction.

        A transport-level failure is treated as UNKNOWN because Kraken
        may have received the request. Such an order must be reconciled
        before any further submission attempt.
        """

        # -------------------------------------------------------------
        # Phase 1:
        # Lock, validate and persist submission intent.
        # No exchange network request occurs inside this transaction.
        # -------------------------------------------------------------

        with transaction.atomic():
            locked_order = (
                Order.objects
                .select_for_update()
                .select_related(
                    "account",
                    "pair",
                    "pair__base_asset",
                    "pair__quote_asset",
                )
                .get(pk=order.pk)
            )

            self._ensure_account_is_live(
                account=account,
            )

            self._ensure_order_belongs_to_account(
                account=account,
                order=locked_order,
            )

            self._ensure_order_can_execute(
                order=locked_order,
            )

            self._validate_order(
                order=locked_order,
            )

            if (
                self.confirmation_required
                and not confirmed
            ):
                raise ValidationError(
                    "Live order confirmation is required."
                )

            self._ensure_live_trading_enabled()

            try:
                pair_info = self.pair_service.resolve(
                    locked_order.pair
                )

                quantity, price = self._prepare_order(
                    order=locked_order,
                    pair_info=pair_info,
                )

            except KrakenPairError as exc:
                raise LiveExecutionError(
                    f"Kraken pair resolution failed: {exc}"
                ) from exc

            exchange_client_order_id = (
                self._kraken_client_order_id(
                    locked_order
                )
            )

            submit_kwargs = {
                "pair": pair_info.kraken_symbol,
                "side": locked_order.side.lower(),
                "order_type": (
                    locked_order.order_type.lower()
                ),
                "volume": self._decimal_string(
                    quantity
                ),
                "client_order_id": (
                    exchange_client_order_id
                ),
            }

            if price is not None:
                submit_kwargs["price"] = (
                    self._decimal_string(price)
                )

            locked_order.exchange_client_order_id = (
                exchange_client_order_id
            )
            locked_order.exchange_order_id = ""
            locked_order.submission_error = ""
            locked_order.submitted_at = timezone.now()
            locked_order.status = Order.Status.SUBMITTING

            locked_order.save(
                update_fields=[
                    "exchange_client_order_id",
                    "exchange_order_id",
                    "submission_error",
                    "submitted_at",
                    "status",
                    "updated_at",
                ]
            )

        # -------------------------------------------------------------
        # Phase 2:
        # The database transaction above has COMMITTED.
        #
        # The Kraken network request intentionally happens here,
        # outside transaction.atomic().
        # -------------------------------------------------------------

        try:
            result = self.adapter.submit_order(
                **submit_kwargs
            )

        except KrakenRejectedError as exc:
            # Kraken explicitly rejected the order. The outcome is
            # definite, so this is not an UNKNOWN submission.
            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=locked_order.pk)
                )

                final_order.status = (
                    Order.Status.REJECTED
                )
                final_order.submission_error = str(exc)

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            raise LiveExecutionError(
                f"Kraken order rejected: {exc}"
            ) from exc

        except KrakenTransportError as exc:
            # We cannot know whether Kraken accepted the order.
            #
            # NEVER automatically resubmit this order. It must first
            # be reconciled using exchange_client_order_id.
            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=locked_order.pk)
                )

                final_order.status = (
                    Order.Status.UNKNOWN
                )
                final_order.submission_error = str(exc)

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            raise LiveExecutionError(
                "Kraken order submission outcome is unknown. "
                "Reconciliation is required before retrying."
            ) from exc

        except KrakenAPIError as exc:
            # Defensive fallback for an API error subtype that has not
            # been classified explicitly. Treat it as UNKNOWN rather
            # than risk submitting the same real order twice.
            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=locked_order.pk)
                )

                final_order.status = (
                    Order.Status.UNKNOWN
                )
                final_order.submission_error = str(exc)

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            raise LiveExecutionError(
                "Kraken order submission outcome is unknown. "
                "Reconciliation is required before retrying."
            ) from exc

        # -------------------------------------------------------------
        # Phase 3:
        # Validate Kraken's successful response before marking OPEN.
        #
        # A malformed success response is also UNKNOWN because the
        # exchange may already have accepted the order.
        # -------------------------------------------------------------

        if not isinstance(result, dict):
            message = (
                "Kraken returned an invalid order response."
            )

            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=locked_order.pk)
                )

                final_order.status = (
                    Order.Status.UNKNOWN
                )
                final_order.submission_error = message

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            raise LiveExecutionError(
                message
                + " Reconciliation is required."
            )

        txids = result.get("txid")

        if (
            not isinstance(txids, list)
            or not txids
            or not all(
                isinstance(txid, str)
                and txid.strip()
                for txid in txids
            )
        ):
            message = (
                "Kraken did not return a valid "
                "order transaction ID."
            )

            with transaction.atomic():
                final_order = (
                    Order.objects
                    .select_for_update()
                    .get(pk=locked_order.pk)
                )

                final_order.status = (
                    Order.Status.UNKNOWN
                )
                final_order.submission_error = message

                final_order.save(
                    update_fields=[
                        "status",
                        "submission_error",
                        "updated_at",
                    ]
                )

            raise LiveExecutionError(
                message
                + " Reconciliation is required."
            )

        # HappyWallet currently submits one Kraken order at a time.
        # Persist the exchange transaction ID returned for that order.
        exchange_order_id = txids[0].strip()

        with transaction.atomic():
            final_order = (
                Order.objects
                .select_for_update()
                .get(pk=locked_order.pk)
            )

            # Only the submission that placed the order into SUBMITTING
            # may complete this transition.
            if (
                final_order.status
                != Order.Status.SUBMITTING
            ):
                raise LiveExecutionError(
                    "Live order state changed while "
                    "Kraken submission was in progress."
                )

            final_order.exchange_order_id = (
                exchange_order_id
            )
            final_order.submission_error = ""
            final_order.status = Order.Status.OPEN

            final_order.save(
                update_fields=[
                    "exchange_order_id",
                    "submission_error",
                    "status",
                    "updated_at",
                ]
            )

        # Kraken acceptance does not mean the order has filled.
        # No Trade record is created here.
        return final_order


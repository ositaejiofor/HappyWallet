"""
HappyWallet Kraken trading-pair service.

This module translates HappyWallet TradingPair objects into Kraken
market metadata.

Safety
------
- Read-only.
- Never submits orders.
- Never modifies TradingPair records.
- Never accesses wallet keys or signing material.
"""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError

from ..models import TradingPair


class KrakenPairError(Exception):
    """Base exception for Kraken trading-pair errors."""


class KrakenPairNotFoundError(KrakenPairError):
    """Raised when a TradingPair cannot be mapped to Kraken."""


@dataclass(frozen=True)
class KrakenPairInfo:
    """Normalized Kraken trading-pair information."""

    happywallet_symbol: str
    kraken_symbol: str

    base_asset: str
    quote_asset: str

    price_precision: int
    quantity_precision: int

    minimum_order_quantity: Decimal

    active: bool


class KrakenPairService:
    """
    Resolve HappyWallet TradingPair objects against Kraken metadata.

    This service is read-only and does not submit orders.
    """

    def __init__(self, adapter):
        self.adapter = adapter

    @staticmethod
    def _asset_symbol(asset):
        """Return an asset symbol normalized to uppercase."""

        symbol = getattr(
            asset,
            "symbol",
            "",
        )

        return str(symbol).strip().upper()

    @staticmethod
    def _decimal(value, field_name):
        """Convert a Kraken numeric value to Decimal."""

        try:
            return Decimal(str(value))
        except (
            InvalidOperation,
            TypeError,
            ValueError,
        ) as exc:
            raise KrakenPairError(
                f"Invalid Kraken value for {field_name}."
            ) from exc

    @staticmethod
    def _matches_assets(
        *,
        info,
        base_asset,
        quote_asset,
    ):
        """
        Determine whether Kraken metadata represents the requested
        base/quote asset combination.
        """

        base = str(
            info.get("base", "")
        ).upper()

        quote = str(
            info.get("quote", "")
        ).upper()

        base_variants = {
            base_asset,
            f"X{base_asset}",
        }

        # Kraken historically uses XXBT for Bitcoin.
        if base_asset == "BTC":
            base_variants.add("XXBT")

        quote_variants = {
            quote_asset,
            f"Z{quote_asset}",
        }

        return (
            base in base_variants
            and quote in quote_variants
        )


    def _find_pair(
        self,
        *,
        pair_data,
        base_asset,
        quote_asset,
    ):
        """
        Find the Kraken pair matching the HappyWallet assets.

        Kraken pair metadata can contain multiple identifiers, so
        asset fields are preferred over assuming symbol equality.
        """

        for kraken_symbol, info in pair_data.items():
            if not isinstance(info, dict):
                continue

            if self._matches_assets(
                info=info,
                base_asset=base_asset,
                quote_asset=quote_asset,
            ):
                return kraken_symbol, info

        return None, None

    def resolve(self, pair: TradingPair):
        """
        Resolve a HappyWallet TradingPair against Kraken.

        Args:
            pair: HappyWallet TradingPair.

        Returns:
            KrakenPairInfo

        Raises:
            ValidationError:
                If the pair is invalid or inactive.

            KrakenPairNotFoundError:
                If Kraken does not expose the pair.

            KrakenPairError:
                If Kraken returns invalid metadata.
        """

        if not isinstance(pair, TradingPair):
            raise ValidationError(
                "A valid TradingPair is required."
            )

        if not pair.is_active:
            raise ValidationError(
                "This trading pair is inactive."
            )

        if not pair.base_asset.is_active:
            raise ValidationError(
                "The base asset is inactive."
            )

        if not pair.quote_asset.is_active:
            raise ValidationError(
                "The quote asset is inactive."
            )

        base_asset = self._asset_symbol(
            pair.base_asset
        )

        quote_asset = self._asset_symbol(
            pair.quote_asset
        )

        if not base_asset:
            raise KrakenPairError(
                "Trading pair base asset has no symbol."
            )

        if not quote_asset:
            raise KrakenPairError(
                "Trading pair quote asset has no symbol."
            )

        pair_data = self.adapter.get_asset_pairs()

        if not isinstance(pair_data, dict):
            raise KrakenPairError(
                "Kraken returned invalid asset-pair data."
            )

        kraken_symbol, info = self._find_pair(
            pair_data=pair_data,
            base_asset=base_asset,
            quote_asset=quote_asset,
        )

        if info is None:
            raise KrakenPairNotFoundError(
                "Kraken trading pair not found for "
                f"{base_asset}/{quote_asset}."
            )

        try:
            price_precision = int(
                info.get(
                    "pair_decimals",
                    pair.price_precision,
                )
            )

            quantity_precision = int(
                info.get(
                    "lot_decimals",
                    pair.quantity_precision,
                )
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise KrakenPairError(
                "Kraken returned invalid precision metadata."
            ) from exc

        if price_precision < 0:
            raise KrakenPairError(
                "Kraken returned invalid price precision."
            )

        if quantity_precision < 0:
            raise KrakenPairError(
                "Kraken returned invalid quantity precision."
            )

        order_min = info.get(
            "ordermin",
            pair.min_order_quantity,
        )

        minimum_order_quantity = self._decimal(
            order_min,
            "ordermin",
        )

        if minimum_order_quantity <= 0:
            raise KrakenPairError(
                "Kraken returned an invalid minimum order quantity."
            )

        altname = str(
            info.get(
                "altname",
                kraken_symbol,
            )
        ).strip().upper()

        if not altname:
            raise KrakenPairError(
                "Kraken returned an invalid pair identifier."
            )

        status = str(
            info.get(
                "status",
                "online",
            )
        ).lower()

        active = status in {
            "online",
            "post_only",
        }

        if not active:
            raise KrakenPairError(
                f"Kraken pair {altname} is not currently active."
            )

        return KrakenPairInfo(
            happywallet_symbol=pair.symbol,
            kraken_symbol=altname,
            base_asset=base_asset,
            quote_asset=quote_asset,
            price_precision=price_precision,
            quantity_precision=quantity_precision,
            minimum_order_quantity=minimum_order_quantity,
            active=True,
        )

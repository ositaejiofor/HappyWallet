from decimal import Decimal
from unittest.mock import Mock

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.market.models import MarketAsset

from .models import TradingPair
from .services.kraken_pairs import (
    KrakenPairError,
    KrakenPairNotFoundError,
    KrakenPairService,
)


class KrakenPairServiceTests(TestCase):
    def setUp(self):
        self.base_asset = MarketAsset.objects.create(
            symbol="btc",
            name="Bitcoin",
            coingecko_id="bitcoin",
            is_active=True,
        )

        self.quote_asset = MarketAsset.objects.create(
            symbol="usdt",
            name="Tether",
            coingecko_id="tether",
            is_active=True,
        )

        self.pair = TradingPair.objects.create(
            base_asset=self.base_asset,
            quote_asset=self.quote_asset,
            symbol="BTC/USDT",
            is_active=True,
            min_order_quantity=Decimal("0.0001"),
            max_order_quantity=Decimal("100"),
            price_precision=2,
            quantity_precision=6,
        )

        self.adapter = Mock()

        self.service = KrakenPairService(
            adapter=self.adapter,
        )

    def _mock_asset_pairs(self):
        self.adapter.get_asset_pairs.return_value = {
            "XBTUSDT": {
                "altname": "XBTUSDT",
                "wsname": "XBT/USDT",
                "base": "XXBT",
                "quote": "USDT",
                "pair_decimals": 2,
                "lot_decimals": 6,
                "ordermin": "0.0001",
                "status": "online",
            },
        }

    def test_resolve_returns_kraken_pair_info(self):
        self._mock_asset_pairs()

        result = self.service.resolve(
            self.pair,
        )

        self.assertEqual(
            result.happywallet_symbol,
            "BTC/USDT",
        )

        self.assertEqual(
            result.kraken_symbol,
            "XBTUSDT",
        )

        self.assertEqual(
            result.base_asset,
            "BTC",
        )

        self.assertEqual(
            result.quote_asset,
            "USDT",
        )

        self.assertEqual(
            result.price_precision,
            2,
        )

        self.assertEqual(
            result.quantity_precision,
            6,
        )

        self.assertEqual(
            result.minimum_order_quantity,
            Decimal("0.0001"),
        )

        self.assertTrue(
            result.active,
        )

    def test_resolve_calls_kraken_asset_pairs(self):
        self._mock_asset_pairs()

        self.service.resolve(
            self.pair,
        )

        self.adapter.get_asset_pairs.assert_called_once_with()

    def test_inactive_trading_pair_is_rejected(self):
        self._mock_asset_pairs()

        self.pair.is_active = False
        self.pair.save(
            update_fields=["is_active"],
        )

        with self.assertRaises(ValidationError):
            self.service.resolve(
                self.pair,
            )

        self.adapter.get_asset_pairs.assert_not_called()

    def test_inactive_base_asset_is_rejected(self):
        self._mock_asset_pairs()

        self.base_asset.is_active = False
        self.base_asset.save(
            update_fields=["is_active"],
        )

        with self.assertRaises(ValidationError):
            self.service.resolve(
                self.pair,
            )

        self.adapter.get_asset_pairs.assert_not_called()

    def test_inactive_quote_asset_is_rejected(self):
        self._mock_asset_pairs()

        self.quote_asset.is_active = False
        self.quote_asset.save(
            update_fields=["is_active"],
        )

        with self.assertRaises(ValidationError):
            self.service.resolve(
                self.pair,
            )

        self.adapter.get_asset_pairs.assert_not_called()

    def test_pair_not_found(self):
        self.adapter.get_asset_pairs.return_value = {
            "ETHUSDT": {
                "altname": "ETHUSDT",
                "base": "XETH",
                "quote": "USDT",
                "pair_decimals": 2,
                "lot_decimals": 5,
                "ordermin": "0.001",
                "status": "online",
            },
        }

        with self.assertRaises(
            KrakenPairNotFoundError,
        ):
            self.service.resolve(
                self.pair,
            )

    def test_invalid_pair_response_is_rejected(self):
        self.adapter.get_asset_pairs.return_value = []

        with self.assertRaises(
            KrakenPairError,
        ):
            self.service.resolve(
                self.pair,
            )

    def test_invalid_minimum_order_is_rejected(self):
        self.adapter.get_asset_pairs.return_value = {
            "XBTUSDT": {
                "altname": "XBTUSDT",
                "base": "XXBT",
                "quote": "USDT",
                "pair_decimals": 2,
                "lot_decimals": 6,
                "ordermin": "0",
                "status": "online",
            },
        }

        with self.assertRaises(
            KrakenPairError,
        ):
            self.service.resolve(
                self.pair,
            )

    def test_inactive_kraken_pair_is_rejected(self):
        self.adapter.get_asset_pairs.return_value = {
            "XBTUSDT": {
                "altname": "XBTUSDT",
                "base": "XXBT",
                "quote": "USDT",
                "pair_decimals": 2,
                "lot_decimals": 6,
                "ordermin": "0.0001",
                "status": "maintenance",
            },
        }

        with self.assertRaises(
            KrakenPairError,
        ):
            self.service.resolve(
                self.pair,
            )

    def test_invalid_precision_is_rejected(self):
        self.adapter.get_asset_pairs.return_value = {
            "XBTUSDT": {
                "altname": "XBTUSDT",
                "base": "XXBT",
                "quote": "USDT",
                "pair_decimals": "invalid",
                "lot_decimals": 6,
                "ordermin": "0.0001",
                "status": "online",
            },
        }

        with self.assertRaises(
            KrakenPairError,
        ):
            self.service.resolve(
                self.pair,
            )

    def test_non_trading_pair_is_rejected(self):
        self._mock_asset_pairs()

        with self.assertRaises(
            ValidationError,
        ):
            self.service.resolve(
                object(),
            )

        self.adapter.get_asset_pairs.assert_not_called()
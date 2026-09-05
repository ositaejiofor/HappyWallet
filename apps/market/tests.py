from decimal import Decimal

from django.test import TestCase

from .models import MarketAsset, MarketPrice


class MarketAssetModelTests(TestCase):
    def setUp(self):
        self.asset = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            chain="ethereum",
            contract_address="",
            decimals=18,
            image_url="https://example.com/eth.png",
            is_active=True,
        )

    def test_market_asset_creation(self):
        self.assertEqual(self.asset.symbol, "ETH")
        self.assertEqual(self.asset.name, "Ethereum")
        self.assertEqual(self.asset.coingecko_id, "ethereum")
        self.assertTrue(self.asset.is_active)

    def test_market_asset_string_representation(self):
        self.assertEqual(
            str(self.asset),
            "Ethereum (ETH)",
        )

    def test_market_asset_defaults(self):
        asset = MarketAsset.objects.create(
            symbol="BTC",
            name="Bitcoin",
            coingecko_id="bitcoin",
        )

        self.assertEqual(asset.chain, "")
        self.assertEqual(asset.contract_address, "")
        self.assertEqual(asset.image_url, "")
        self.assertIsNone(asset.decimals)
        self.assertTrue(asset.is_active)


class MarketPriceModelTests(TestCase):
    def setUp(self):
        self.asset = MarketAsset.objects.create(
            symbol="ETH",
            name="Ethereum",
            coingecko_id="ethereum",
            decimals=18,
        )

        self.price = MarketPrice.objects.create(
            asset=self.asset,
            price_usd=Decimal("2452.370000000000"),
            market_cap_usd=Decimal("295000000000.00"),
            volume_24h_usd=Decimal("15000000000.00"),
            price_change_24h=Decimal("2.350000"),
            circulating_supply=Decimal("120000000.000000000000"),
            fully_diluted_valuation_usd=Decimal("300000000000.00"),
        )

    def test_market_price_creation(self):
        self.assertEqual(self.price.asset, self.asset)
        self.assertEqual(
            self.price.price_usd,
            Decimal("2452.370000000000"),
        )

    def test_market_price_string_representation(self):
        self.assertEqual(
            str(self.price),
            "ETH @ $2452.370000000000",
        )

    def test_market_price_optional_fields(self):
        price = MarketPrice.objects.create(
            asset=self.asset,
            price_usd=Decimal("2500"),
        )

        self.assertIsNone(price.market_cap_usd)
        self.assertIsNone(price.volume_24h_usd)
        self.assertIsNone(price.price_change_24h)
        self.assertIsNone(price.circulating_supply)
        self.assertIsNone(price.fully_diluted_valuation_usd)

    def test_asset_can_have_multiple_price_snapshots(self):
        MarketPrice.objects.create(
            asset=self.asset,
            price_usd=Decimal("2500"),
        )

        self.assertEqual(
            MarketPrice.objects.filter(
                asset=self.asset,
            ).count(),
            2,
        )

    def test_prices_are_related_to_asset(self):
        self.assertIn(
            self.price,
            self.asset.prices.all(),
        )
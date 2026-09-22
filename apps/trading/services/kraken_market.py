"""
Normalized read-only Kraken public market prices.

This service uses only Kraken's public Ticker endpoint. It never reads
account balances, submits orders, or requires API credentials.
"""

from decimal import Decimal, InvalidOperation

from django.utils import timezone

from .kraken import KrakenAPIError, KrakenAdapter


class KrakenPublicMarketService:
    """Retrieve normalized public prices from Kraken."""

    SUPPORTED_PAIRS = (
        {
            "symbol": "BTC/USD",
            "kraken_pair": "XBTUSD",
        },
        {
            "symbol": "ETH/USD",
            "kraken_pair": "ETHUSD",
        },
        {
            "symbol": "SOL/USD",
            "kraken_pair": "SOLUSD",
        },
        {
            "symbol": "XRP/USD",
            "kraken_pair": "XRPUSD",
        },
        {
            "symbol": "TRX/USD",
            "kraken_pair": "TRXUSD",
        },
    )

    def __init__(self, adapter=None):
        self.adapter = adapter or KrakenAdapter()

    @staticmethod
    def _decimal(value, field_name):
        try:
            return Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise KrakenAPIError(
                f"Kraken returned an invalid {field_name} value."
            ) from exc

    @staticmethod
    def _ticker_entry(result):
        if not isinstance(result, dict) or not result:
            raise KrakenAPIError(
                "Kraken returned an empty ticker result."
            )

        entry = next(iter(result.values()))

        if not isinstance(entry, dict):
            raise KrakenAPIError(
                "Kraken returned malformed ticker data."
            )

        return entry

    def get_price(self, symbol, kraken_pair):
        result = self.adapter.get_ticker(kraken_pair)
        ticker = self._ticker_entry(result)

        try:
            last = self._decimal(ticker["c"][0], "last price")
            bid = self._decimal(ticker["b"][0], "bid price")
            ask = self._decimal(ticker["a"][0], "ask price")
            high = self._decimal(ticker["h"][1], "24-hour high")
            low = self._decimal(ticker["l"][1], "24-hour low")
            volume = self._decimal(ticker["v"][1], "24-hour volume")
            opening = self._decimal(ticker["o"], "opening price")
        except (KeyError, IndexError, TypeError) as exc:
            raise KrakenAPIError(
                "Kraken returned incomplete ticker data."
            ) from exc

        change = last - opening

        if opening:
            change_percentage = (
                change / opening
            ) * Decimal("100")
        else:
            change_percentage = Decimal("0")

        return {
            "symbol": symbol,
            "kraken_pair": kraken_pair,
            "price": str(last),
            "bid": str(bid),
            "ask": str(ask),
            "high_24h": str(high),
            "low_24h": str(low),
            "volume_24h": str(volume),
            "change_24h": str(change),
            "change_percentage_24h": str(
                change_percentage.quantize(
                    Decimal("0.01")
                )
            ),
        }

    def get_prices(self):
        prices = []

        for pair in self.SUPPORTED_PAIRS:
            prices.append(
                self.get_price(
                    pair["symbol"],
                    pair["kraken_pair"],
                )
            )

        return {
            "provider": "Kraken",
            "currency": "USD",
            "retrieved_at": timezone.now().isoformat(),
            "prices": prices,
        }
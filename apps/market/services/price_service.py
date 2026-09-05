"""
Public market-price service interface.

The implementation lives in the providers package. This module provides
the stable import path used by the market application.
"""

from .providers.price_service import MarketPriceService

__all__ = ["MarketPriceService"]

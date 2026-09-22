# apps/wallet/services/wallet_balance.py

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from apps.blockchain.models import Asset, BlockchainNetwork
from apps.wallet.models import Wallet

from .address import WalletAddressService
from .balance import (
    TokenBalance,
    WalletBalance,
    WalletBalanceService,
)
from .tron_balance import TronWalletBalanceService


TRON_NETWORK_IDENTIFIERS = frozenset(
    {
        "tron",
        "tron-mainnet",
        "tron-main-net",
        "trx",
        "trx-mainnet",
    }
)


# ============================================================================
# RESULT
# ============================================================================


@dataclass(frozen=True, slots=True)
class WalletDashboardBalance:
    """
    Immutable, dashboard-ready representation of public blockchain state.

    This object contains public wallet information only.

    It must never contain:

    - mnemonic
    - recovery phrase
    - seed
    - private key
    - decrypted secret material
    - signing information
    """

    wallet: Wallet

    address: str

    network: str
    network_symbol: str

    native_symbol: str
    native_balance: Decimal

    tokens: tuple[TokenBalance, ...]

    asset_count: int

    blockchain_available: bool

    # ========================================================================
    # DERIVED STATE
    # ========================================================================

    @property
    def has_balance(self) -> bool:
        """
        Return True when the blockchain query succeeded and the wallet has
        a non-zero native or token balance.

        An unavailable blockchain must never be interpreted as zero balance.
        """

        if not self.blockchain_available:
            return False

        if self.native_balance > Decimal("0"):
            return True

        return any(
            token.balance > Decimal("0")
            for token in self.tokens
        )

    @property
    def token_balances(self) -> tuple[TokenBalance, ...]:
        """
        Backwards-compatible alias for ``tokens``.
        """

        return self.tokens

    @property
    def has_token_balances(self) -> bool:
        """
        Return True when blockchain data is available and at least one
        configured token balance was returned.
        """

        return bool(
            self.blockchain_available
            and self.tokens
        )

    @property
    def display_native_balance(self) -> str:
        """
        Return a presentation-safe native balance.

        ``—`` is returned when blockchain state is unavailable so that a
        failed RPC request cannot be displayed as a confirmed zero balance.
        """

        if not self.blockchain_available:
            return "—"

        return format(
            self.native_balance,
            "f",
        )

    @property
    def display_network(self) -> str:
        """
        Return the network name suitable for dashboard display.
        """

        return self.network or "Unknown Network"

    @property
    def display_symbol(self) -> str:
        """
        Return the native/network symbol suitable for dashboard display.
        """

        return (
            self.native_symbol
            or self.network_symbol
            or "—"
        )


# ============================================================================
# SERVICE
# ============================================================================


class WalletDashboardBalanceService:
    """
    Resolve live public blockchain balances for a wallet.

    Responsibilities
    ----------------
    - Validate the wallet.
    - Resolve the configured network.
    - Resolve the authoritative public wallet address.
    - Resolve configured token assets.
    - Query public blockchain state.
    - Convert the result into immutable dashboard data.

    Address authority
    -----------------
    WalletAddress is the authoritative public address record.

    Wallet.address is only a compatibility mirror maintained by
    WalletAddressService.

    Security boundary
    -----------------
    This service:

    - never accepts a mnemonic
    - never handles private keys
    - never decrypts wallet secrets
    - never signs transactions
    - never broadcasts transactions
    - never persists blockchain balances
    - never modifies wallet records
    - only reads public blockchain state

    Dependency injection
    --------------------
    The address and balance services may be replaced with test doubles
    without changing dashboard logic.
    """

    def __init__(
        self,
        *,
        balance_service_class: type[
            WalletBalanceService
        ] = WalletBalanceService,
        address_service: WalletAddressService | None = None,
    ) -> None:
        self.balance_service_class = (
            balance_service_class
        )

        self.address_service = (
            address_service
            or WalletAddressService()
        )

    # ========================================================================
    # PUBLIC API
    # ========================================================================

    def get(
        self,
        *,
        wallet: Wallet,
    ) -> WalletDashboardBalance:
        """
        Retrieve the current live public blockchain balance.

        Provider/configuration failures are converted into a safe
        ``blockchain_available=False`` result so that the dashboard remains
        available.
        """

        self._validate_wallet(
            wallet,
        )

        network = self._get_network(
            wallet=wallet,
        )

        if network is None:
            return self._empty_result(
                wallet=wallet,
            )

        address = self._get_wallet_address(
            wallet=wallet,
            network=network,
        )

        if not address:
            return self._empty_result(
                wallet=wallet,
            )

        assets = self._get_token_assets(
            network=network,
        )

        try:
            balance_service_class = self._get_balance_service_class(
                network=network,
            )
            balance_service = (
                balance_service_class(
                    network=network,
                )
            )

            result = balance_service.get_wallet_balance(
                address=address,
                assets=assets,
            )

        except (
            ValueError,
            RuntimeError,
        ):
            return self._empty_result(
                wallet=wallet,
                address=address,
            )

        except Exception:
            # Provider implementations may expose provider-specific
            # exceptions. The dashboard must remain available when the
            # external blockchain provider is temporarily unavailable.
            return self._empty_result(
                wallet=wallet,
                address=address,
            )

        return self._build_result(
            wallet=wallet,
            network=network,
            result=result,
        )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    @staticmethod
    def _validate_wallet(
        wallet: Wallet | None,
    ) -> None:
        """
        Validate the wallet argument.
        """

        if wallet is None:
            raise ValueError(
                "A wallet is required."
            )

        if not isinstance(
            wallet,
            Wallet,
        ):
            raise ValueError(
                "A valid Wallet instance is required."
            )

    # ========================================================================
    # NETWORK
    # ========================================================================

    def _get_balance_service_class(
        self,
        *,
        network: BlockchainNetwork,
    ) -> type[WalletBalanceService] | type[TronWalletBalanceService]:
        """Select TRON only for the default production service mapping.

        Explicitly injected test doubles retain precedence.
        """

        if self.balance_service_class is not WalletBalanceService:
            return self.balance_service_class

        candidates = (
            getattr(network, "slug", ""),
            getattr(network, "code", ""),
            getattr(network, "name", ""),
            getattr(network, "symbol", ""),
        )

        for candidate in candidates:
            if not isinstance(candidate, str):
                continue

            normalized = (
                candidate.strip().lower().replace("_", "-").replace(" ", "-")
            )

            if normalized in TRON_NETWORK_IDENTIFIERS:
                return TronWalletBalanceService

        return WalletBalanceService

    @staticmethod
    def _get_network(
        *,
        wallet: Wallet,
    ) -> BlockchainNetwork | None:
        """
        Return the wallet's configured blockchain network.
        """

        return getattr(
            wallet,
            "network",
            None,
        )

    # ========================================================================
    # RESULT BUILDING
    # ========================================================================

    @staticmethod
    def _build_result(
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
        result: WalletBalance,
    ) -> WalletDashboardBalance:
        """
        Convert the low-level blockchain result into immutable dashboard data.
        """

        network_name = (
            network.name.strip()
            if network.name
            else "Unknown Network"
        )

        network_symbol = (
            network.symbol.strip()
            if network.symbol
            else ""
        )

        native_symbol = (
            result.native.symbol.strip()
            if result.native.symbol
            else network_symbol
        )

        return WalletDashboardBalance(
            wallet=wallet,

            address=(
                result.address or ""
            ).strip(),

            network=network_name,

            network_symbol=network_symbol,

            native_symbol=native_symbol,

            native_balance=result.native.balance,

            tokens=tuple(
                result.tokens
            ),

            asset_count=result.total_asset_count,

            blockchain_available=True,
        )

    # ========================================================================
    # WALLET ADDRESS
    # ========================================================================

    def _get_wallet_address(
        self,
        *,
        wallet: Wallet,
        network: BlockchainNetwork,
    ) -> str:
        """
        Return the authoritative public blockchain address.

        WalletAddressService is the single address-resolution boundary.

        WalletAddress is authoritative.

        Wallet.address is only used internally by WalletAddressService as
        a compatibility fallback where appropriate.

        No private wallet material is accessed.
        """

        return self.address_service.get_address_string(
            wallet=wallet,
            network=network,
        )

    # ========================================================================
    # TOKEN ASSETS
    # ========================================================================

    @staticmethod
    def _get_token_assets(
        *,
        network: BlockchainNetwork,
    ) -> tuple[Asset, ...]:
        """
        Return active non-native assets configured for the network.

        Asset records are the source of truth for:

        - contract address
        - token name
        - token symbol
        - decimal precision
        - network ownership
        - active state
        """

        return tuple(
            Asset.objects
            .filter(
                network=network,
                is_active=True,
                is_native=False,
            )
            .exclude(
                contract_address__isnull=True,
            )
            .exclude(
                contract_address="",
            )
            .order_by(
                "symbol",
                "name",
            )
        )

    # ========================================================================
    # EMPTY / UNAVAILABLE RESULT
    # ========================================================================

    def _empty_result(
        self,
        *,
        wallet: Wallet,
        address: str | None = None,
    ) -> WalletDashboardBalance:
        """
        Return a safe unavailable dashboard result.

        ``native_balance=0`` does NOT mean the blockchain confirmed a
        zero balance.

        ``blockchain_available=False`` is the authoritative indicator
        that the live balance query did not successfully complete.

        When an authoritative address was already resolved, it is preserved
        in the result even though blockchain state is unavailable.
        """

        network = getattr(
            wallet,
            "network",
            None,
        )

        network_name = (
            network.name.strip()
            if network and network.name
            else "Not configured"
        )

        network_symbol = (
            network.symbol.strip()
            if network and network.symbol
            else ""
        )

        if address is None and network is not None:
            try:
                address = self._get_wallet_address(
                    wallet=wallet,
                    network=network,
                )
            except Exception:
                address = ""

        return WalletDashboardBalance(
            wallet=wallet,

            address=(
                address or ""
            ).strip(),

            network=network_name,

            network_symbol=network_symbol,

            native_symbol=network_symbol,

            native_balance=Decimal("0"),

            tokens=(),

            asset_count=0,

            blockchain_available=False,
        )


# ============================================================================
# DEFAULT SERVICE
# ============================================================================


wallet_dashboard_balance_service = (
    WalletDashboardBalanceService()
)


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================


def get_wallet_dashboard_balance(
    wallet: Wallet,
) -> WalletDashboardBalance:
    """
    Return the current live public dashboard balance.
    """

    return wallet_dashboard_balance_service.get(
        wallet=wallet,
    )

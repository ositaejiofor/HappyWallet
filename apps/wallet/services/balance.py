# apps/wallet/services/balance.py

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Iterable

from web3 import Web3
from web3.exceptions import Web3Exception

from apps.blockchain.models import Asset, BlockchainNetwork
from apps.blockchain.services.network import (
    BlockchainNetworkService,
)


# ============================================================================
# CONSTANTS
# ============================================================================

RPC_TIMEOUT = 15
DEFAULT_NATIVE_DECIMALS = 18
MAX_TOKEN_DECIMALS = 36


# ============================================================================
# ERC-20 ABI
# ============================================================================

ERC20_ABI = [
    {
        "inputs": [
            {
                "name": "account",
                "type": "address",
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "",
                "type": "uint256",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "",
                "type": "uint8",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "symbol",
        "outputs": [
            {
                "name": "",
                "type": "string",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "",
                "type": "string",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


# ============================================================================
# RESULT TYPES
# ============================================================================


@dataclass(frozen=True, slots=True)
class NativeBalance:
    """Read-only native blockchain balance."""

    symbol: str
    balance: Decimal
    raw_balance: int
    decimals: int


@dataclass(frozen=True, slots=True)
class TokenBalance:
    """Read-only ERC-20 token balance."""

    address: str
    name: str
    symbol: str
    balance: Decimal
    raw_balance: int
    decimals: int
    asset_id: str | None = None


@dataclass(frozen=True, slots=True)
class WalletBalance:
    """Complete read-only wallet balance."""

    address: str
    network: str
    native: NativeBalance
    tokens: tuple[TokenBalance, ...]

    @property
    def total_asset_count(self) -> int:
        """Return the number of represented assets."""

        return 1 + len(self.tokens)


# ============================================================================
# SERVICE
# ============================================================================


class WalletBalanceService:
    """
    Read-only blockchain balance service.

    Responsibilities
    ----------------
    - Resolve blockchain network configuration.
    - Connect to the configured RPC endpoint.
    - Validate the connected chain.
    - Read native blockchain balances.
    - Read configured ERC-20 balances.
    - Convert base units into Decimal values.

    Security
    --------
    This service:

    - never accepts recovery phrases
    - never accepts private keys
    - never signs transactions
    - never broadcasts transactions
    - never modifies wallet records
    - never modifies blockchain state
    """

    def __init__(
        self,
        *,
        network: BlockchainNetwork,
        network_service: BlockchainNetworkService | None = None,
        timeout: int = RPC_TIMEOUT,
    ) -> None:
        self.network = self._validate_network(network)

        self.network_service = (
            network_service
            or BlockchainNetworkService()
        )

        self.configuration = self.network_service.get(
            network=self.network,
        )

        self.rpc_url = self.configuration.rpc_url

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": timeout,
                },
            )
        )

    # ========================================================================
    # CONNECTION
    # ========================================================================

    def is_connected(self) -> bool:
        """Return True when the RPC endpoint is reachable."""

        try:
            return bool(
                self.web3.is_connected()
            )
        except Exception:
            return False

    def get_chain_id(self) -> int:
        """Return the chain ID reported by the RPC endpoint."""

        if not self.is_connected():
            raise RuntimeError(
                "Blockchain RPC endpoint is unavailable."
            )

        try:
            return int(
                self.web3.eth.chain_id
            )
        except Exception as exc:
            raise RuntimeError(
                "Unable to determine blockchain network."
            ) from exc

    def validate_chain(self) -> bool:
        """
        Verify that the RPC endpoint matches the configured network.
        """

        expected_chain_id = self.network.chain_id

        if expected_chain_id is None:
            return True

        actual_chain_id = self.get_chain_id()

        if actual_chain_id != int(expected_chain_id):
            raise RuntimeError(
                "Blockchain RPC chain ID does not match "
                "the configured network."
            )

        return True

    # ========================================================================
    # NATIVE BALANCE
    # ========================================================================

    def get_native_balance(
        self,
        *,
        address: str,
    ) -> NativeBalance:
        """Retrieve the native blockchain balance."""

        checksum_address = self._validate_address(
            address
        )

        symbol = (
            self.network.symbol.strip()
            or "ETH"
        )

        decimals = DEFAULT_NATIVE_DECIMALS

        try:
            raw_balance = int(
                self.web3.eth.get_balance(
                    checksum_address
                )
            )
        except Web3Exception as exc:
            raise RuntimeError(
                "Unable to retrieve native wallet balance."
            ) from exc

        balance = self._from_base_units(
            raw_balance,
            decimals,
        )

        return NativeBalance(
            symbol=symbol,
            balance=balance,
            raw_balance=raw_balance,
            decimals=decimals,
        )

    # ========================================================================
    # TOKEN BALANCE
    # ========================================================================

    def get_token_balance(
        self,
        *,
        wallet_address: str,
        asset: Asset,
    ) -> TokenBalance:
        """Retrieve an ERC-20 token balance."""

        self._validate_asset(
            asset
        )

        checksum_wallet = self._validate_address(
            wallet_address
        )

        token_address = (
            asset.contract_address or ""
        ).strip()

        if not token_address:
            raise ValueError(
                "Asset does not have a contract address."
            )

        checksum_token = self._validate_address(
            token_address
        )

        try:
            contract = self.web3.eth.contract(
                address=checksum_token,
                abi=ERC20_ABI,
            )

            raw_balance = int(
                contract.functions.balanceOf(
                    checksum_wallet
                ).call()
            )

        except Exception as exc:
            raise RuntimeError(
                "Unable to retrieve token balance."
            ) from exc

        decimals = self._validate_decimals(
            asset.decimals
        )

        balance = self._from_base_units(
            raw_balance,
            decimals,
        )

        return TokenBalance(
            address=checksum_token,
            name=asset.name,
            symbol=asset.symbol,
            balance=balance,
            raw_balance=raw_balance,
            decimals=decimals,
            asset_id=str(asset.pk),
        )

    # ========================================================================
    # SUPPORTED ASSETS
    # ========================================================================

    def get_supported_assets(
        self,
    ) -> tuple[Asset, ...]:
        """
        Return active non-native token assets configured
        for the current blockchain network.
        """

        queryset = (
            Asset.objects
            .filter(
                network=self.network,
                is_active=True,
                is_native=False,
            )
            .exclude(
                contract_address=""
            )
            .exclude(
                contract_address__isnull=True
            )
            .order_by(
                "symbol",
                "name",
            )
        )

        return tuple(queryset)

    # ========================================================================
    # TOKEN BALANCES
    # ========================================================================

    def get_token_balances(
        self,
        *,
        wallet_address: str,
        assets: Iterable[Asset] | None = None,
    ) -> tuple[TokenBalance, ...]:
        """
        Retrieve balances for configured token assets.

        A failure for one token does not prevent other tokens
        from being returned.
        """

        configured_assets = (
            tuple(assets)
            if assets is not None
            else self.get_supported_assets()
        )

        balances: list[TokenBalance] = []

        for asset in configured_assets:
            try:
                balance = self.get_token_balance(
                    wallet_address=wallet_address,
                    asset=asset,
                )
            except (
                ValueError,
                RuntimeError,
            ):
                continue

            balances.append(
                balance
            )

        return tuple(balances)

    # ========================================================================
    # COMPLETE WALLET BALANCE
    # ========================================================================

    def get_wallet_balance(
        self,
        *,
        address: str,
        assets: Iterable[Asset] | None = None,
        token_addresses: Iterable[str] | None = None,
    ) -> WalletBalance:
        """
        Retrieve the complete public balance for a wallet.

        ``assets`` is the preferred API because Asset records contain
        the authoritative token metadata.

        ``token_addresses`` is retained as a compatibility option.
        """

        checksum_address = self._validate_address(
            address
        )

        if not self.is_connected():
            raise RuntimeError(
                "Blockchain RPC endpoint is unavailable."
            )

        self.validate_chain()

        native = self.get_native_balance(
            address=checksum_address,
        )

        if assets is not None:
            tokens = self.get_token_balances(
                wallet_address=checksum_address,
                assets=assets,
            )

        elif token_addresses is not None:
            tokens = self._get_token_balances_from_addresses(
                wallet_address=checksum_address,
                token_addresses=token_addresses,
            )

        else:
            tokens = self.get_token_balances(
                wallet_address=checksum_address,
            )

        return WalletBalance(
            address=checksum_address,
            network=self.network.name,
            native=native,
            tokens=tokens,
        )

    # ========================================================================
    # COMPATIBILITY TOKEN LOOKUP
    # ========================================================================

    def _get_token_balances_from_addresses(
        self,
        *,
        wallet_address: str,
        token_addresses: Iterable[str],
    ) -> tuple[TokenBalance, ...]:
        """
        Resolve token contract addresses against active Asset records.

        This keeps compatibility with callers that still provide
        ``token_addresses`` while Asset remains the source of truth.
        """

        addresses = {
            address.strip().lower()
            for address in token_addresses
            if isinstance(address, str)
            and address.strip()
        }

        if not addresses:
            return ()

        assets = (
            Asset.objects
            .filter(
                network=self.network,
                is_active=True,
                is_native=False,
            )
            .exclude(
                contract_address=""
            )
            .exclude(
                contract_address__isnull=True
            )
        )

        matching_assets = tuple(
            asset
            for asset in assets
            if (
                asset.contract_address
                and asset.contract_address.strip().lower()
                in addresses
            )
        )

        return self.get_token_balances(
            wallet_address=wallet_address,
            assets=matching_assets,
        )

    # ========================================================================
    # VALIDATION
    # ========================================================================

    @staticmethod
    def _validate_network(
        network: BlockchainNetwork,
    ) -> BlockchainNetwork:
        """Validate the blockchain network model."""

        if not isinstance(
            network,
            BlockchainNetwork,
        ):
            raise ValueError(
                "A valid BlockchainNetwork is required."
            )

        if not network.is_active:
            raise ValueError(
                "Blockchain network is inactive."
            )

        return network

    @staticmethod
    def _validate_address(
        address: str,
    ) -> str:
        """
        Validate and checksum an EVM-compatible address.

        Address conversion is deliberately handled by Web3
        rather than manually manipulating hexadecimal strings.
        """

        if not isinstance(
            address,
            str,
        ):
            raise ValueError(
                "Blockchain address must be a string."
            )

        address = address.strip()

        if not address:
            raise ValueError(
                "Blockchain address is required."
            )

        if not Web3.is_address(
            address
        ):
            raise ValueError(
                "Invalid blockchain address."
            )

        try:
            return Web3.to_checksum_address(
                address
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid blockchain address."
            ) from exc

    def _validate_asset(
        self,
        asset: Asset,
    ) -> None:
        """Validate an Asset before querying its contract."""

        if not isinstance(
            asset,
            Asset,
        ):
            raise ValueError(
                "A valid Asset is required."
            )

        if asset.network_id != self.network.id:
            raise ValueError(
                "Asset does not belong to the configured network."
            )

        if not asset.is_active:
            raise ValueError(
                "Asset is inactive."
            )

        if asset.is_native:
            raise ValueError(
                "Native assets cannot be queried as ERC-20 contracts."
            )

    @staticmethod
    def _validate_decimals(
        decimals: int,
    ) -> int:
        """Validate blockchain decimal precision."""

        try:
            decimals = int(decimals)
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "Asset decimal precision is invalid."
            ) from exc

        if not 0 <= decimals <= MAX_TOKEN_DECIMALS:
            raise ValueError(
                "Asset decimal precision is outside the supported range."
            )

        return decimals

    # ========================================================================
    # DECIMAL CONVERSION
    # ========================================================================

    @staticmethod
    def _from_base_units(
        raw_amount: int,
        decimals: int,
    ) -> Decimal:
        """
        Convert blockchain base units into Decimal.

        Example:

            1000000000000000000 -> 1 ETH
        """

        if not isinstance(
            raw_amount,
            int,
        ):
            raise ValueError(
                "Blockchain amount must be an integer."
            )

        if raw_amount < 0:
            raise ValueError(
                "Blockchain amount cannot be negative."
            )

        decimals = WalletBalanceService._validate_decimals(
            decimals
        )

        return (
            Decimal(raw_amount)
            / (
                Decimal(10)
                ** decimals
            )
        )


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================


def get_wallet_balance(
    *,
    network: BlockchainNetwork,
    address: str,
    assets: Iterable[Asset] | None = None,
) -> WalletBalance:
    """
    Convenience wrapper for WalletBalanceService.
    """

    return WalletBalanceService(
        network=network,
    ).get_wallet_balance(
        address=address,
        assets=assets,
    )
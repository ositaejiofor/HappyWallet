"""
HappyWallet Token Scanner - DEX Discovery.

This module performs READ-ONLY discovery of decentralized-exchange
liquidity pools from public EVM blockchain state.

Security guarantees
-------------------
- No private keys.
- No seed phrases.
- No transaction signing.
- No transaction submission.
- No token approvals.
- No swaps.
- No automatic buying.
- No automatic selling.
- No fabricated liquidity data.

This service discovers pools from actual on-chain factory events.

It does NOT:

- execute trades
- provide trading instructions
- estimate profitability
- claim liquidity is locked
- claim a token is safe
- fabricate USD liquidity
- fabricate pool addresses

The service is intentionally generic and does not assume that a
particular DEX exists unless its factory configuration is explicitly
provided by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from web3 import Web3
from web3.exceptions import Web3Exception


# ============================================================================
# Constants
# ============================================================================

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_LOG_CHUNK_SIZE = 10
DEFAULT_MAX_BLOCKS = 100
DEFAULT_MAX_POOLS = 100

MIN_TIMEOUT_SECONDS = 0.1
MIN_LOG_CHUNK_SIZE = 1
MIN_MAX_BLOCKS = 1
MIN_MAX_POOLS = 1


# ============================================================================
# PairCreated event
# ============================================================================

PAIR_CREATED_EVENT_SIGNATURE = (
    "PairCreated(address,address,address,uint256)"
)

PAIR_CREATED_EVENT_TOPIC = (
    "0x"
    + Web3.keccak(
        text=PAIR_CREATED_EVENT_SIGNATURE
    ).hex().removeprefix("0x")
)


# ============================================================================
# Exceptions
# ============================================================================


class DexDiscoveryError(Exception):
    """Base exception for DEX discovery."""


class DexDiscoveryConfigurationError(DexDiscoveryError):
    """Raised when DEX discovery configuration is invalid."""


class DexDiscoveryRPCError(DexDiscoveryError):
    """Raised when a blockchain RPC operation fails."""


# ============================================================================
# Data structures
# ============================================================================


@dataclass(frozen=True)
class DexFactory:
    """
    Configuration describing an on-chain DEX factory.

    The factory address and event signature must come from a real
    deployed contract configuration.

    No factory is invented by this service.
    """

    name: str
    address: str
    pair_created_topic: str = PAIR_CREATED_EVENT_TOPIC

    def __post_init__(self) -> None:
        """Validate and normalize factory configuration."""

        if not isinstance(self.name, str) or not self.name.strip():
            raise DexDiscoveryConfigurationError(
                "Factory name must be a non-empty string."
            )

        if (
            not isinstance(self.address, str)
            or not self.address.strip()
        ):
            raise DexDiscoveryConfigurationError(
                "Factory address must be a non-empty "
                "Ethereum address."
            )

        try:
            normalized_address = Web3.to_checksum_address(
                self.address.strip()
            )
        except (TypeError, ValueError) as exc:
            raise DexDiscoveryConfigurationError(
                "Factory address must be a valid "
                "Ethereum address."
            ) from exc

        object.__setattr__(
            self,
            "address",
            normalized_address,
        )

        topic = self._normalize_topic_configuration(
            self.pair_created_topic
        )

        object.__setattr__(
            self,
            "pair_created_topic",
            topic,
        )

    @staticmethod
    def _normalize_topic_configuration(
        value: Any,
    ) -> str:
        """
        Validate and canonicalize a factory event topic.

        Returns:

            0x + 64 hexadecimal characters
        """

        if not isinstance(value, str):
            raise DexDiscoveryConfigurationError(
                "pair_created_topic must be a string."
            )

        topic = value.strip()

        if not topic:
            raise DexDiscoveryConfigurationError(
                "pair_created_topic must be a "
                "non-empty string."
            )

        if topic.lower().startswith("0x"):
            topic = topic[2:]

        if len(topic) != 64:
            raise DexDiscoveryConfigurationError(
                "pair_created_topic must contain "
                "exactly 32 bytes of hexadecimal data."
            )

        try:
            int(topic, 16)
        except ValueError as exc:
            raise DexDiscoveryConfigurationError(
                "pair_created_topic must be valid "
                "hexadecimal data."
            ) from exc

        return "0x" + topic.lower()


@dataclass(frozen=True)
class DexPool:
    """
    A real liquidity pool discovered from a DEX factory event.
    """

    dex_name: str
    factory_address: str
    pool_address: str
    token0: str
    token1: str
    block_number: int
    transaction_hash: str

    @property
    def tokens(self) -> tuple[str, str]:
        """Return the two pool token addresses."""

        return self.token0, self.token1


@dataclass(frozen=True)
class DexDiscoveryResult:
    """
    Immutable result of one bounded DEX discovery operation.
    """

    from_block: int
    to_block: int

    pools: tuple[DexPool, ...] = field(
        default_factory=tuple
    )

    logs_examined: int = 0
    pools_discovered: int = 0
    factories_examined: int = 0

    complete: bool = False

    warnings: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def pool_count(self) -> int:
        """Return the number of discovered pools."""

        return len(self.pools)

    @property
    def block_count(self) -> int:
        """Return the number of scanned blocks."""

        return self.to_block - self.from_block + 1


# ============================================================================
# Discovery service
# ============================================================================


class EthereumDexDiscovery:
    """
    Read-only DEX liquidity-pool discovery service.

    The service scans configured DEX factory contracts for pool creation
    events.

    It deliberately does not assume that every DEX uses the same factory
    event. A DexFactory configuration specifies the factory address and
    event topic.

    The default event topic represents the common Uniswap V2-style:

        PairCreated(address,address,address,uint256)

    No financial information is fabricated.

    Security boundary
    -----------------
    This service only reads blockchain state through Web3.py.

    It does not:

    - sign transactions
    - submit transactions
    - create approvals
    - execute swaps
    - transfer tokens
    - buy tokens
    - sell tokens
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        factories: Iterable[DexFactory] = (),
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        log_chunk_size: int = DEFAULT_LOG_CHUNK_SIZE,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
        max_pools: int = DEFAULT_MAX_POOLS,
    ) -> None:
        self._validate_configuration(
            rpc_url=rpc_url,
            timeout=timeout,
            log_chunk_size=log_chunk_size,
            max_blocks=max_blocks,
            max_pools=max_pools,
        )

        self.rpc_url = rpc_url.strip()
        self.timeout = float(timeout)
        self.log_chunk_size = int(log_chunk_size)
        self.max_blocks = int(max_blocks)
        self.max_pools = int(max_pools)

        self.factories = tuple(factories)

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": self.timeout,
                },
            )
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def latest_block(self) -> int:
        """
        Return the latest block reported by the configured RPC.

        This is a read-only blockchain operation.
        """

        self._ensure_connection()

        try:
            return int(
                self.web3.eth.block_number
            )

        except Web3Exception as exc:
            raise DexDiscoveryRPCError(
                "Unable to retrieve the latest Ethereum block."
            ) from exc

        except Exception as exc:
            raise DexDiscoveryRPCError(
                "Unexpected error retrieving the latest "
                "Ethereum block."
            ) from exc

    def discover(
        self,
        *,
        from_block: int,
        to_block: int | None = None,
    ) -> DexDiscoveryResult:
        """
        Discover liquidity pools created by configured DEX factories.

        The scan is bounded by max_blocks.

        If no factories are configured, the result contains no pools
        and a warning explaining that DEX discovery requires explicit
        factory configuration.

        RPC connectivity is only required when actual factory discovery
        will be performed.

        ``complete`` means the requested discovery operation completed
        without an internal discovery failure. It does not mean that
        pools were necessarily found.
        """

        start = self._validate_block_number(
            from_block,
            field_name="from_block",
        )

        if to_block is None:
            end = self.latest_block()
        else:
            end = self._validate_block_number(
                to_block,
                field_name="to_block",
            )

        self._validate_range(
            from_block=start,
            to_block=end,
            max_blocks=self.max_blocks,
        )

        # No configured factories means there is nothing to query.
        #
        # The operation itself completed normally, therefore complete=True.
        # The warning explicitly communicates that no DEX discovery occurred.
        if not self.factories:
            return DexDiscoveryResult(
                from_block=start,
                to_block=end,
                pools=(),
                logs_examined=0,
                pools_discovered=0,
                factories_examined=0,
                complete=True,
                warnings=(
                    "No DEX factories are configured. "
                    "Pool discovery was not performed.",
                ),
            )

        self._ensure_connection()

        pools: list[DexPool] = []
        warnings: list[str] = []
        logs_examined = 0
        complete = True

        for factory in self.factories:
            try:
                factory_pools, factory_logs = (
                    self._discover_factory(
                        factory=factory,
                        from_block=start,
                        to_block=end,
                    )
                )

                logs_examined += factory_logs

                for pool in factory_pools:
                    if len(pools) >= self.max_pools:
                        break

                    pools.append(pool)

            except DexDiscoveryError as exc:
                complete = False

                warnings.append(
                    f"DEX factory {factory.name} "
                    f"({factory.address}) failed: "
                    f"{exc}"
                )

        if len(pools) >= self.max_pools:
            complete = False

            warnings.append(
                "DEX pool result limit reached: "
                f"max_pools={self.max_pools}."
            )

        return DexDiscoveryResult(
            from_block=start,
            to_block=end,
            pools=tuple(pools),
            logs_examined=logs_examined,
            pools_discovered=len(pools),
            factories_examined=len(self.factories),
            complete=complete,
            warnings=tuple(
                dict.fromkeys(warnings)
            ),
        )

    # =========================================================================
    # Factory discovery
    # =========================================================================

    def _discover_factory(
        self,
        *,
        factory: DexFactory,
        from_block: int,
        to_block: int,
    ) -> tuple[tuple[DexPool, ...], int]:
        """
        Discover pools from one DEX factory.

        Returns:

            (
                discovered pools,
                raw factory logs examined
            )
        """

        pools: list[DexPool] = []
        logs_examined = 0

        start = from_block

        while start <= to_block:
            end = min(
                start + self.log_chunk_size - 1,
                to_block,
            )

            logs = self._get_factory_logs(
                factory=factory,
                from_block=start,
                to_block=end,
            )

            logs_examined += len(logs)

            for log in logs:
                pool = self._pool_from_log(
                    factory=factory,
                    log=log,
                )

                if pool is None:
                    continue

                pools.append(pool)

                if len(pools) >= self.max_pools:
                    return (
                        tuple(pools),
                        logs_examined,
                    )

            start = end + 1

        return (
            tuple(pools),
            logs_examined,
        )

    def _get_factory_logs(
        self,
        *,
        factory: DexFactory,
        from_block: int,
        to_block: int,
    ) -> list[Any]:
        """
        Retrieve factory creation events from the RPC.

        Uses a bounded eth_getLogs request. Block numbers are
        explicitly encoded as hexadecimal JSON-RPC quantities so
        the request is compatible with RPC providers such as
        Alchemy Free tier.
        """

        try:
            logs = self.web3.eth.get_logs(
                {
                    "address": factory.address,
                    "fromBlock": hex(from_block),
                    "toBlock": hex(to_block),
                    "topics": [
                        factory.pair_created_topic
                    ],
                }
            )

            return list(logs)

        except Web3Exception as exc:
            raise DexDiscoveryRPCError(
                "Ethereum RPC failed while reading "
                f"{factory.name} factory logs for "
                f"blocks {from_block}-{to_block}: "
                f"{exc}"
            ) from exc

        except Exception as exc:
            raise DexDiscoveryRPCError(
                "Unexpected error while reading "
                f"{factory.name} factory logs for "
                f"blocks {from_block}-{to_block}: "
                f"{exc}"
            ) from exc

    # =========================================================================
    # Event parsing
    # =========================================================================

    def _pool_from_log(
        self,
        *,
        factory: DexFactory,
        log: Any,
    ) -> DexPool | None:
        """
        Convert a PairCreated-style event into a DexPool.

        Standard Uniswap V2-style event:

            topics[0] = PairCreated event signature
            topics[1] = token0
            topics[2] = token1

        Data:

            first 32 bytes  = pair address
            second 32 bytes = pair creation index
        """

        if not hasattr(log, "get"):
            return None

        address = self._normalize_address(
            log.get("address")
        )

        if address is None:
            return None

        if address.lower() != factory.address.lower():
            return None

        topics = log.get("topics")

        if not isinstance(
            topics,
            (list, tuple),
        ):
            return None

        if len(topics) < 3:
            return None

        event_topic = self._normalize_topic(
            topics[0]
        )

        if event_topic is None:
            return None

        if (
            event_topic.lower()
            != factory.pair_created_topic.lower()
        ):
            return None

        token0 = self._decode_indexed_address(
            topics[1]
        )

        token1 = self._decode_indexed_address(
            topics[2]
        )

        if token0 is None or token1 is None:
            return None

        pool_address = self._decode_pool_address(
            log.get("data")
        )

        if pool_address is None:
            return None

        block_number = self._extract_block_number(
            log.get("blockNumber")
        )

        if block_number is None:
            return None

        transaction_hash = (
            self._normalize_transaction_hash(
                log.get("transactionHash")
            )
        )

        if transaction_hash is None:
            return None

        return DexPool(
            dex_name=factory.name,
            factory_address=factory.address,
            pool_address=pool_address,
            token0=token0,
            token1=token1,
            block_number=block_number,
            transaction_hash=transaction_hash,
        )

    # =========================================================================
    # Decoding helpers
    # =========================================================================

    @staticmethod
    def _normalize_topic(
        value: Any,
    ) -> str | None:
        """
        Normalize an EVM topic into canonical hexadecimal form.

        The returned value always has:

            0x + 64 hexadecimal characters
        """

        if value is None:
            return None

        if isinstance(value, bytes):
            raw = value.hex()

        elif isinstance(value, str):
            raw = value.strip()

            if not raw:
                return None

            raw = raw.removeprefix("0x")

        elif hasattr(value, "hex"):
            try:
                raw = value.hex()
            except Exception:
                return None

            if not isinstance(raw, str):
                return None

            raw = raw.removeprefix("0x")

        else:
            return None

        if len(raw) != 64:
            return None

        try:
            int(raw, 16)
        except ValueError:
            return None

        return "0x" + raw.lower()

    @staticmethod
    def _decode_indexed_address(
        value: Any,
    ) -> str | None:
        """
        Decode an indexed Solidity address.

        Indexed address topics are 32 bytes with the 20-byte
        address right-aligned.
        """

        raw = EthereumDexDiscovery._coerce_hex_bytes(
            value
        )

        if raw is None:
            return None

        if len(raw) != 32:
            return None

        address = "0x" + raw[-20:].hex()

        try:
            return Web3.to_checksum_address(
                address
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _decode_pool_address(
        value: Any,
    ) -> str | None:
        """
        Decode the first ABI-encoded address from PairCreated data.

        PairCreated's non-indexed portion is:

            address pair
            uint256 pairCount

        Each ABI word is 32 bytes.

        The address occupies the final 20 bytes of the first
        32-byte word.
        """

        raw = EthereumDexDiscovery._coerce_hex_bytes(
            value
        )

        if raw is None:
            return None

        if len(raw) < 32:
            return None

        address = "0x" + raw[12:32].hex()

        try:
            return Web3.to_checksum_address(
                address
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_hex_bytes(
        value: Any,
    ) -> bytes | None:
        """
        Convert supported raw RPC hexadecimal representations to bytes.

        This helper is deliberately restricted to decoding paths.

        It is NOT used by _normalize_address(), because ordinary
        address normalization accepts string addresses only.
        """

        if isinstance(value, bytes):
            return value

        if isinstance(value, str):
            raw = value.strip()

            if not raw:
                return None

            raw = raw.removeprefix("0x")

            try:
                return bytes.fromhex(raw)
            except ValueError:
                return None

        if hasattr(value, "hex"):
            try:
                raw = value.hex()
            except Exception:
                return None

            if not isinstance(raw, str):
                return None

            raw = raw.removeprefix("0x")

            try:
                return bytes.fromhex(raw)
            except ValueError:
                return None

        return None

    # =========================================================================
    # Connection / configuration
    # =========================================================================

    def _ensure_connection(self) -> None:
        """
        Ensure the Ethereum RPC endpoint is reachable.

        This performs a connectivity check only.
        """

        try:
            if not self.web3.is_connected():
                raise DexDiscoveryRPCError(
                    "Ethereum RPC endpoint is not connected."
                )

        except DexDiscoveryRPCError:
            raise

        except Exception as exc:
            raise DexDiscoveryRPCError(
                "Unable to connect to the Ethereum RPC endpoint."
            ) from exc

    @staticmethod
    def _validate_configuration(
        *,
        rpc_url: str,
        timeout: float,
        log_chunk_size: int,
        max_blocks: int,
        max_pools: int,
    ) -> None:
        """Validate service configuration."""

        if not isinstance(rpc_url, str):
            raise DexDiscoveryConfigurationError(
                "rpc_url must be a non-empty string."
            )

        if not rpc_url.strip():
            raise DexDiscoveryConfigurationError(
                "rpc_url must be a non-empty string."
            )

        if isinstance(timeout, bool):
            raise DexDiscoveryConfigurationError(
                "timeout must be a positive number."
            )

        try:
            timeout_value = float(timeout)
        except (TypeError, ValueError) as exc:
            raise DexDiscoveryConfigurationError(
                "timeout must be a positive number."
            ) from exc

        if timeout_value < MIN_TIMEOUT_SECONDS:
            raise DexDiscoveryConfigurationError(
                f"timeout must be >= "
                f"{MIN_TIMEOUT_SECONDS}."
            )

        if isinstance(log_chunk_size, bool):
            raise DexDiscoveryConfigurationError(
                "log_chunk_size must be an integer."
            )

        if not isinstance(log_chunk_size, int):
            raise DexDiscoveryConfigurationError(
                "log_chunk_size must be an integer."
            )

        if log_chunk_size < MIN_LOG_CHUNK_SIZE:
            raise DexDiscoveryConfigurationError(
                "log_chunk_size must be at least 1."
            )

        if isinstance(max_blocks, bool):
            raise DexDiscoveryConfigurationError(
                "max_blocks must be an integer."
            )

        if not isinstance(max_blocks, int):
            raise DexDiscoveryConfigurationError(
                "max_blocks must be an integer."
            )

        if max_blocks < MIN_MAX_BLOCKS:
            raise DexDiscoveryConfigurationError(
                "max_blocks must be at least 1."
            )

        if isinstance(max_pools, bool):
            raise DexDiscoveryConfigurationError(
                "max_pools must be an integer."
            )

        if not isinstance(max_pools, int):
            raise DexDiscoveryConfigurationError(
                "max_pools must be an integer."
            )

        if max_pools < MIN_MAX_POOLS:
            raise DexDiscoveryConfigurationError(
                "max_pools must be at least 1."
            )

    @staticmethod
    def _validate_range(
        *,
        from_block: int,
        to_block: int,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
    ) -> None:
        """
        Validate a bounded block range.
        """

        if from_block > to_block:
            raise DexDiscoveryConfigurationError(
                "from_block cannot be greater than to_block."
            )

        block_count = to_block - from_block + 1

        if block_count > max_blocks:
            raise DexDiscoveryConfigurationError(
                f"Block range exceeds max_blocks={max_blocks}."
            )

    @staticmethod
    def _validate_block_number(
        value: Any,
        *,
        field_name: str,
    ) -> int:
        """
        Validate an Ethereum block number.
        """

        if isinstance(value, bool):
            raise DexDiscoveryConfigurationError(
                f"{field_name} must be a non-negative integer."
            )

        if not isinstance(value, int):
            raise DexDiscoveryConfigurationError(
                f"{field_name} must be a non-negative integer."
            )

        if value < 0:
            raise DexDiscoveryConfigurationError(
                f"{field_name} must be a non-negative integer."
            )

        return value

    @staticmethod
    def _extract_block_number(
        value: Any,
    ) -> int | None:
        """
        Extract a valid block number from raw RPC data.
        """

        if value is None or isinstance(value, bool):
            return None

        try:
            block_number = int(value)
        except (TypeError, ValueError):
            return None

        if block_number < 0:
            return None

        return block_number

    @staticmethod
    def _normalize_address(
        value: Any,
    ) -> str | None:
        """
        Normalize a string Ethereum address.

        Raw bytes and arbitrary hex-like objects are deliberately
        rejected here.

        Byte-oriented blockchain data must be decoded explicitly by
        _decode_indexed_address() or _decode_pool_address().
        """

        if not isinstance(value, str):
            return None

        value = value.strip()

        if not value:
            return None

        try:
            return Web3.to_checksum_address(
                value
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_transaction_hash(
        value: Any,
    ) -> str | None:
        """
        Normalize an Ethereum transaction hash.

        Transaction hashes may arrive from Web3.py as:

        - bytes
        - strings
        - hex-compatible objects

        The result is always returned as:

            0x + lowercase hexadecimal
        """

        if value is None:
            return None

        if isinstance(value, bytes):
            raw = value.hex()

        elif isinstance(value, str):
            raw = value.strip()

            if not raw:
                return None

            raw = raw.removeprefix("0x")

        elif hasattr(value, "hex"):
            try:
                raw = value.hex()
            except Exception:
                return None

            if not isinstance(raw, str):
                return None

            raw = raw.removeprefix("0x")

        else:
            return None

        if not raw:
            return None

        try:
            int(raw, 16)
        except ValueError:
            return None

        return "0x" + raw.lower()
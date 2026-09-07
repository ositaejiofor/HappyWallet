"""
HappyWallet Token Scanner - Demand Analysis.

Read-only analysis of public ERC-20 / DEX activity.

This service does NOT:
    - execute swaps
    - approve tokens
    - sign transactions
    - access private keys
    - access seed phrases
    - place orders

Important:
    ERC-20 Transfer events alone do not prove that a transfer was a
    market buy or sell.

For that reason, this module uses known liquidity-pool addresses.
A transfer involving a configured pool can then be classified as:

    pool -> trader      BUY
    trader -> pool      SELL

Transfers between ordinary wallets are classified as transfers,
not buys or sells.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable

from web3 import Web3
from web3.exceptions import Web3Exception


# ============================================================================
# Constants
# ============================================================================

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

TRANSFER_EVENT_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a"
    "3e6f0f9c"
)


# ============================================================================
# Exceptions
# ============================================================================


class DemandAnalysisError(Exception):
    """Base exception for demand analysis."""


class InvalidDemandAddressError(DemandAnalysisError):
    """Raised when an address is invalid."""


class DemandRPCError(DemandAnalysisError):
    """Raised when blockchain RPC access fails."""


# ============================================================================
# Result objects
# ============================================================================


@dataclass(frozen=True)
class DemandEvent:
    """
    Normalized token market-activity event.

    event_type:
        buy
        sell
        transfer
        mint
        burn
    """

    event_type: str

    block_number: int

    transaction_index: int

    log_index: int

    transaction_hash: str

    from_address: str

    to_address: str

    amount_raw: int

    amount: Decimal

    pool_address: str | None = None

    trader_address: str | None = None


@dataclass(frozen=True)
class DemandAnalysis:
    """
    Aggregate demand analysis for a token over a block range.
    """

    token_address: str

    scanned_from_block: int

    scanned_to_block: int

    buy_count: int

    sell_count: int

    transfer_count: int

    mint_count: int

    burn_count: int

    unique_buyers: int

    unique_sellers: int

    buy_volume: Decimal

    sell_volume: Decimal

    total_observed_volume: Decimal

    buy_sell_ratio: Decimal | None

    buy_volume_ratio: Decimal | None

    demand_pressure: Decimal | None

    events: tuple[DemandEvent, ...] = field(
        default_factory=tuple
    )

    warnings: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def net_buy_volume(self) -> Decimal:
        """
        Difference between observed buy and sell volume.
        """

        return (
            self.buy_volume
            - self.sell_volume
        )

    @property
    def net_buy_count(self) -> int:
        """
        Difference between buy and sell transaction/event counts.
        """

        return (
            self.buy_count
            - self.sell_count
        )

    @property
    def has_positive_demand(self) -> bool:
        """
        Return True when observed buy volume exceeds sell volume.
        """

        return (
            self.buy_volume > self.sell_volume
        )


# ============================================================================
# Analyzer
# ============================================================================


class EVMDemandAnalyzer:
    """
    Analyze token demand using ERC-20 Transfer events.

    Parameters
    ----------
    rpc_url:
        Ethereum-compatible JSON-RPC endpoint.

    timeout:
        RPC request timeout.

    log_chunk_size:
        Maximum number of blocks per eth_getLogs request.

    max_events:
        Maximum number of events retained in memory.

    Notes
    -----
    The caller must provide known liquidity-pool addresses.

    This is deliberate. Arbitrarily guessing that an address is a DEX
    pool would produce unreliable buy/sell classifications.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = 10.0,
        log_chunk_size: int = 2_000,
        max_events: int = 50_000,
    ) -> None:
        if not isinstance(rpc_url, str) or not rpc_url.strip():
            raise ValueError(
                "rpc_url must be a non-empty string."
            )

        if log_chunk_size < 1:
            raise ValueError(
                "log_chunk_size must be at least 1."
            )

        if max_events < 1:
            raise ValueError(
                "max_events must be at least 1."
            )

        self.rpc_url = rpc_url.strip()
        self.log_chunk_size = log_chunk_size
        self.max_events = max_events

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": timeout,
                },
            )
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        token_address: str,
        *,
        pool_addresses: Iterable[str],
        from_block: int,
        to_block: int | None = None,
        decimals: int = 18,
    ) -> DemandAnalysis:
        """
        Analyze token demand within a bounded block range.

        Parameters
        ----------
        token_address:
            ERC-20 token contract.

        pool_addresses:
            Known liquidity-pool addresses for the token.

        from_block:
            First block to scan.

        to_block:
            Last block to scan.

        decimals:
            ERC-20 decimals.

        Returns
        -------
        DemandAnalysis
        """

        token = self._validate_address(
            token_address
        )

        pools = {
            self._validate_address(address).lower()
            for address in pool_addresses
        }

        if not pools:
            raise DemandAnalysisError(
                "At least one liquidity-pool address is required."
            )

        self._validate_block_range(
            from_block=from_block,
            to_block=to_block,
        )

        if decimals < 0 or decimals > 255:
            raise ValueError(
                "decimals must be between 0 and 255."
            )

        if to_block is None:
            to_block = self._get_latest_block()

        logs = self._get_transfer_logs(
            token_address=token,
            from_block=from_block,
            to_block=to_block,
        )

        events = self._classify_events(
            logs=logs,
            pool_addresses=pools,
            decimals=decimals,
        )

        if len(events) > self.max_events:
            events = events[-self.max_events:]

        buy_events = [
            event
            for event in events
            if event.event_type == "buy"
        ]

        sell_events = [
            event
            for event in events
            if event.event_type == "sell"
        ]

        transfer_events = [
            event
            for event in events
            if event.event_type == "transfer"
        ]

        mint_events = [
            event
            for event in events
            if event.event_type == "mint"
        ]

        burn_events = [
            event
            for event in events
            if event.event_type == "burn"
        ]

        unique_buyers = {
            event.trader_address.lower()
            for event in buy_events
            if event.trader_address
        }

        unique_sellers = {
            event.trader_address.lower()
            for event in sell_events
            if event.trader_address
        }

        buy_volume = sum(
            (
                event.amount
                for event in buy_events
            ),
            Decimal("0"),
        )

        sell_volume = sum(
            (
                event.amount
                for event in sell_events
            ),
            Decimal("0"),
        )

        total_volume = (
            buy_volume
            + sell_volume
        )

        buy_sell_ratio = None

        if sell_events:
            buy_sell_ratio = (
                Decimal(len(buy_events))
                / Decimal(len(sell_events))
            ).quantize(
                Decimal("0.01")
            )

        buy_volume_ratio = None

        if total_volume > 0:
            buy_volume_ratio = (
                buy_volume
                / total_volume
                * Decimal("100")
            ).quantize(
                Decimal("0.01")
            )

        demand_pressure = self._calculate_demand_pressure(
            buy_volume=buy_volume,
            sell_volume=sell_volume,
        )

        warnings: list[str] = []

        if not buy_events and not sell_events:
            warnings.append(
                "No pool-directed buys or sells were observed "
                "in the scanned range."
            )

        if (
            buy_volume > 0
            and sell_volume > 0
            and buy_volume > sell_volume * Decimal("3")
        ):
            warnings.append(
                "Observed buy volume is more than three times "
                "observed sell volume."
            )

        if (
            sell_volume > 0
            and buy_volume > 0
            and sell_volume > buy_volume * Decimal("3")
        ):
            warnings.append(
                "Observed sell volume is more than three times "
                "observed buy volume."
            )

        return DemandAnalysis(
            token_address=token,
            scanned_from_block=from_block,
            scanned_to_block=to_block,
            buy_count=len(buy_events),
            sell_count=len(sell_events),
            transfer_count=len(transfer_events),
            mint_count=len(mint_events),
            burn_count=len(burn_events),
            unique_buyers=len(unique_buyers),
            unique_sellers=len(unique_sellers),
            buy_volume=buy_volume,
            sell_volume=sell_volume,
            total_observed_volume=total_volume,
            buy_sell_ratio=buy_sell_ratio,
            buy_volume_ratio=buy_volume_ratio,
            demand_pressure=demand_pressure,
            events=tuple(events),
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Demand pressure
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_demand_pressure(
        *,
        buy_volume: Decimal,
        sell_volume: Decimal,
    ) -> Decimal | None:
        """
        Calculate normalized demand pressure.

        Formula:

            (buy - sell) / (buy + sell) * 100

        Therefore:

            +100 = only buys observed
              0 = equal buy/sell volume
            -100 = only sells observed

        This is a descriptive metric, not a price prediction.
        """

        total = (
            buy_volume
            + sell_volume
        )

        if total <= 0:
            return None

        pressure = (
            (buy_volume - sell_volume)
            / total
            * Decimal("100")
        )

        return pressure.quantize(
            Decimal("0.01")
        )

    # ------------------------------------------------------------------
    # Transfer logs
    # ------------------------------------------------------------------


def _get_transfer_logs(
    self,
    *,
    token_address: str,
    from_block: int,
    to_block: int,
) -> list[Any]:
    """
    Retrieve ERC-20 Transfer events in bounded, retryable chunks.

    The Ethereum JSON-RPC ``eth_getLogs`` method is subject to
    provider-specific block-range and response-size limits.

    This implementation therefore:

        1. Scans the requested range incrementally.
        2. Retries transient RPC failures.
        3. Reduces the chunk size when a provider rejects a range.
        4. Never skips a block range silently.
        5. Preserves the original exception as the cause.
        6. Never exposes the configured RPC URL in errors.

    No transaction is submitted and no wallet credentials are used.
    """

    logs: list[Any] = []

    current = from_block

    # Start with the configured chunk size.  If the provider rejects
    # a range, the value is reduced for subsequent requests.
    chunk_size = self.log_chunk_size

    # Prevent the adaptive logic from reducing the request to zero.
    min_chunk_size = 1

    # A small retry count is sufficient for transient provider errors.
    max_attempts = 3

    while current <= to_block:
        chunk_end = min(
            current + chunk_size - 1,
            to_block,
        )

        attempts = 0

        while True:
            attempts += 1

            try:
                chunk = self.web3.eth.get_logs(
                    {
                        "address": token_address,
                        "topics": [
                            TRANSFER_EVENT_TOPIC,
                        ],
                        "fromBlock": current,
                        "toBlock": chunk_end,
                    }
                )

                logs.extend(chunk)

                # The request succeeded.  Move forward without
                # skipping any blocks.
                current = chunk_end + 1

                # If we previously reduced the chunk size and this
                # request succeeded, cautiously grow it again.
                if chunk_size < self.log_chunk_size:
                    chunk_size = min(
                        self.log_chunk_size,
                        chunk_size * 2,
                    )

                break

            except Web3Exception as exc:
                if attempts < max_attempts:
                    continue

                # If the provider rejected the range, reduce the
                # chunk size and retry the same block range.
                if chunk_size > min_chunk_size:
                    chunk_size = max(
                        min_chunk_size,
                        chunk_size // 2,
                    )

                    chunk_end = min(
                        current + chunk_size - 1,
                        to_block,
                    )

                    continue

                raise DemandRPCError(
                    (
                        "Unable to retrieve Transfer logs for "
                        f"blocks {current}-{chunk_end} "
                        f"after {max_attempts} attempts "
                        f"({type(exc).__name__})."
                    )
                ) from exc

            except Exception as exc:
                if attempts < max_attempts:
                    continue

                if chunk_size > min_chunk_size:
                    chunk_size = max(
                        min_chunk_size,
                        chunk_size // 2,
                    )

                    chunk_end = min(
                        current + chunk_size - 1,
                        to_block,
                    )

                    continue

                raise DemandRPCError(
                    (
                        "Unexpected error retrieving Transfer logs "
                        f"for blocks {current}-{chunk_end} "
                        f"after {max_attempts} attempts "
                        f"({type(exc).__name__})."
                    )
                ) from exc

    return logs


    # ------------------------------------------------------------------
    # Event classification
    # ------------------------------------------------------------------

    def _classify_events(
        self,
        *,
        logs: Iterable[Any],
        pool_addresses: set[str],
        decimals: int,
    ) -> list[DemandEvent]:
        """
        Classify Transfer events.

        Classification rules:

            zero -> trader
                MINT

            trader -> zero/dead
                BURN

            pool -> trader
                BUY

            trader -> pool
                SELL

            otherwise
                TRANSFER
        """

        ordered_logs = sorted(
            logs,
            key=self._log_sort_key,
        )

        events: list[DemandEvent] = []

        for log in ordered_logs:
            parsed = self._parse_transfer_log(
                log
            )

            if parsed is None:
                continue

            from_address, to_address, amount_raw = parsed

            from_lower = (
                from_address.lower()
                if from_address
                else ""
            )

            to_lower = (
                to_address.lower()
                if to_address
                else ""
            )

            if from_lower == ZERO_ADDRESS.lower():
                event_type = "mint"
                trader_address = to_address
                pool_address = None

            elif to_lower == ZERO_ADDRESS.lower():
                event_type = "burn"
                trader_address = from_address
                pool_address = None

            elif from_lower in pool_addresses:
                event_type = "buy"
                trader_address = to_address
                pool_address = from_address

            elif to_lower in pool_addresses:
                event_type = "sell"
                trader_address = from_address
                pool_address = to_address

            else:
                event_type = "transfer"
                trader_address = None
                pool_address = None

            amount = (
                Decimal(amount_raw)
                / (Decimal("10") ** decimals)
            )

            transaction_hash = self._transaction_hash(
                log
            )

            events.append(
                DemandEvent(
                    event_type=event_type,
                    block_number=int(
                        log.get(
                            "blockNumber",
                            0,
                        )
                    ),
                    transaction_index=int(
                        log.get(
                            "transactionIndex",
                            0,
                        )
                    ),
                    log_index=int(
                        log.get(
                            "logIndex",
                            0,
                        )
                    ),
                    transaction_hash=transaction_hash,
                    from_address=from_address
                    or ZERO_ADDRESS,
                    to_address=to_address
                    or ZERO_ADDRESS,
                    amount_raw=amount_raw,
                    amount=amount,
                    pool_address=pool_address,
                    trader_address=trader_address,
                )
            )

        return events

    # ------------------------------------------------------------------
    # Log parsing
    # ------------------------------------------------------------------

    def _parse_transfer_log(
        self,
        log: Any,
    ) -> tuple[str, str, int] | None:
        topics = log.get(
            "topics",
            [],
        )

        if len(topics) < 3:
            return None

        try:
            from_address = self._topic_address(
                topics[1]
            )

            to_address = self._topic_address(
                topics[2]
            )

            amount = self._decode_uint256(
                log.get(
                    "data",
                    "0x0",
                )
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

        return (
            from_address,
            to_address,
            amount,
        )

    @staticmethod
    def _topic_address(
        topic: Any,
    ) -> str:
        """
        Decode an indexed address from a 32-byte topic.
        """

        if isinstance(topic, bytes):
            value = topic.hex()
        else:
            value = str(topic)

        if value.startswith("0x"):
            value = value[2:]

        if len(value) != 64:
            raise ValueError(
                "Invalid indexed address topic."
            )

        return Web3.to_checksum_address(
            "0x" + value[-40:]
        )

    @staticmethod
    def _decode_uint256(
        data: Any,
    ) -> int:
        """
        Decode the uint256 event amount.
        """

        if isinstance(data, bytes):
            return int.from_bytes(
                data,
                byteorder="big",
            )

        value = str(data)

        if value.startswith("0x"):
            return int(
                value[2:] or "0",
                16,
            )

        return int(value)

    @staticmethod
    def _transaction_hash(
        log: Any,
    ) -> str:
        """
        Normalize transaction hash to a hex string.
        """

        value = log.get(
            "transactionHash",
            "",
        )

        if isinstance(value, bytes):
            return "0x" + value.hex()

        return str(value)

    @staticmethod
    def _log_sort_key(
        log: Any,
    ) -> tuple[int, int, int]:
        return (
            int(
                log.get(
                    "blockNumber",
                    0,
                )
            ),
            int(
                log.get(
                    "transactionIndex",
                    0,
                )
            ),
            int(
                log.get(
                    "logIndex",
                    0,
                )
            ),
        )

    # ------------------------------------------------------------------
    # Block validation
    # ------------------------------------------------------------------

    def _validate_block_range(
        self,
        *,
        from_block: int,
        to_block: int | None,
    ) -> None:
        if not isinstance(
            from_block,
            int,
        ):
            raise ValueError(
                "from_block must be an integer."
            )

        if from_block < 0:
            raise ValueError(
                "from_block cannot be negative."
            )

        if to_block is not None:
            if not isinstance(
                to_block,
                int,
            ):
                raise ValueError(
                    "to_block must be an integer."
                )

            if to_block < from_block:
                raise ValueError(
                    "to_block cannot be earlier than from_block."
                )

    def _get_latest_block(self) -> int:
        try:
            return int(
                self.web3.eth.block_number
            )

        except Web3Exception as exc:
            raise DemandRPCError(
                "Unable to retrieve latest block."
            ) from exc

        except Exception as exc:
            raise DemandRPCError(
                "Unexpected error retrieving latest block."
            ) from exc

    # ------------------------------------------------------------------
    # Address validation
    # ------------------------------------------------------------------

    def _validate_address(
        self,
        address: str,
    ) -> str:
        if not isinstance(
            address,
            str,
        ):
            raise InvalidDemandAddressError(
                "Address must be a string."
            )

        address = address.strip()

        if not address:
            raise InvalidDemandAddressError(
                "Address is required."
            )

        if not self.web3.is_address(
            address
        ):
            raise InvalidDemandAddressError(
                f"Invalid EVM address: {address}"
            )

        return self.web3.to_checksum_address(
            address
        )
"""
HappyWallet Token Scanner - Holder Analysis.

Read-only ERC-20 holder distribution analysis.

Security rules:
    - Never request private keys.
    - Never request seed phrases.
    - Never sign transactions.
    - Never submit transactions.
    - Never approve token spending.
    - Never execute swaps.

Holder balances are reconstructed from ERC-20 Transfer events within
a bounded block range.

IMPORTANT:
    A bounded event scan does not necessarily represent the complete
    lifetime holder distribution of a token. Callers should therefore
    treat complete_history=False unless the scan starts from the token's
    deployment/genesis point and the implementation has enough history
    to establish completeness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from web3 import Web3
from web3.exceptions import Web3Exception


# ============================================================================
# Constants
# ============================================================================

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

DEAD_ADDRESS = "0x000000000000000000000000000000000000dead"

TRANSFER_EVENT_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a"
    "3e6f0f9c"
)


# ============================================================================
# Exceptions
# ============================================================================


class HolderAnalysisError(Exception):
    """Base exception for holder analysis."""


class InvalidHolderAddressError(HolderAnalysisError):
    """Raised when an address is invalid."""


class HolderRPCError(HolderAnalysisError):
    """Raised when blockchain RPC access fails."""


# ============================================================================
# Result objects
# ============================================================================


@dataclass(frozen=True)
class HolderBalance:
    """
    Normalized holder balance.

    This contains public blockchain information only.
    """

    address: str
    balance_raw: int
    balance: Decimal


@dataclass(frozen=True)
class HolderAnalysis:
    """
    Aggregate ERC-20 holder distribution analysis.
    """

    token_address: str

    scanned_from_block: int
    scanned_to_block: int

    holder_count: int

    top_10_holder_percentage: Decimal | None

    total_observed_balance: Decimal

    complete_history: bool = False

    holders: tuple[HolderBalance, ...] = field(
        default_factory=tuple
    )

    warnings: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def has_holders(self) -> bool:
        """Return True when at least one positive-balance holder exists."""

        return self.holder_count > 0


# ============================================================================
# Analyzer
# ============================================================================


class EVMHolderAnalyzer:
    """
    Reconstruct ERC-20 holder balances from Transfer events.

    Parameters
    ----------
    rpc_url:
        Ethereum-compatible JSON-RPC endpoint.

    timeout:
        HTTP request timeout in seconds.

    log_chunk_size:
        Maximum number of blocks queried per eth_getLogs request.

    Notes
    -----
    This is a bounded event reconstruction mechanism.

    It cannot reliably determine holders that existed before the beginning
    of the scanned range unless the scan starts sufficiently early.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = 10.0,
        log_chunk_size: int = 2_000,
    ) -> None:
        if not isinstance(rpc_url, str) or not rpc_url.strip():
            raise ValueError(
                "rpc_url must be a non-empty string."
            )

        if log_chunk_size < 1:
            raise ValueError(
                "log_chunk_size must be at least 1."
            )

        self.rpc_url = rpc_url.strip()
        self.log_chunk_size = log_chunk_size

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": timeout,
                },
            )
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def analyze(
        self,
        token_address: str,
        *,
        from_block: int,
        to_block: int | None = None,
        decimals: int = 18,
        complete_history: bool = False,
    ) -> HolderAnalysis:
        """
        Reconstruct holder balances within a bounded block range.

        Parameters
        ----------
        token_address:
            ERC-20 token contract address.

        from_block:
            First block to scan.

        to_block:
            Last block to scan. Defaults to latest block.

        decimals:
            ERC-20 decimals.

        complete_history:
            Whether the caller has established that the event range
            represents complete token history.

        Returns
        -------
        HolderAnalysis
        """

        token = self._validate_address(
            token_address
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

        balances_raw = self._reconstruct_balances(
            logs
        )

        holders = self._build_holders(
            balances_raw=balances_raw,
            decimals=decimals,
        )

        total_balance = sum(
            (
                holder.balance
                for holder in holders
            ),
            Decimal("0"),
        )

        top_10_percentage = (
            self._calculate_top_10_percentage(
                holders=holders,
                total_balance=total_balance,
            )
        )

        warnings: list[str] = []

        if not complete_history:
            warnings.append(
                "Holder distribution is reconstructed from a bounded "
                "Transfer-event scan and may not represent all holders."
            )

        if not holders:
            warnings.append(
                "No positive-balance holders were reconstructed in the "
                "scanned range."
            )

        if (
            top_10_percentage is not None
            and top_10_percentage >= Decimal("90")
        ):
            warnings.append(
                "The top 10 observed holders control at least 90% "
                "of the reconstructed balance."
            )

        return HolderAnalysis(
            token_address=token,
            scanned_from_block=from_block,
            scanned_to_block=to_block,
            holder_count=len(holders),
            top_10_holder_percentage=top_10_percentage,
            total_observed_balance=total_balance,
            complete_history=complete_history,
            holders=tuple(holders),
            warnings=tuple(warnings),
        )

    # =========================================================================
    # Transfer logs
    # =========================================================================

    def _get_transfer_logs(
        self,
        *,
        token_address: str,
        from_block: int,
        to_block: int,
    ) -> list[Any]:
        """
        Retrieve ERC-20 Transfer logs in bounded chunks.
        """

        logs: list[Any] = []

        current = from_block

        while current <= to_block:
            chunk_end = min(
                current + self.log_chunk_size - 1,
                to_block,
            )

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

            except Web3Exception as exc:
                raise HolderRPCError(
                    (
                        "Unable to retrieve Transfer logs for "
                        f"blocks {current}-{chunk_end}."
                    )
                ) from exc

            except Exception as exc:
                raise HolderRPCError(
                    (
                        "Unexpected error retrieving Transfer logs "
                        f"for blocks {current}-{chunk_end}."
                    )
                ) from exc

            logs.extend(chunk)

            current = chunk_end + 1

        return logs

    # =========================================================================
    # Balance reconstruction
    # =========================================================================

    def _reconstruct_balances(
        self,
        logs: list[Any],
    ) -> dict[str, int]:
        """
        Reconstruct balances from Transfer events.

        Important:
            This reconstruction is only valid relative to the beginning
            of the supplied event range.

        If holders already possessed tokens before from_block, their
        pre-existing balances are unknown.
        """

        balances: dict[str, int] = {}

        ordered_logs = sorted(
            logs,
            key=self._log_sort_key,
        )

        for log in ordered_logs:
            parsed = self._parse_transfer_log(
                log
            )

            if parsed is None:
                continue

            from_address, to_address, amount = parsed

            from_lower = from_address.lower()
            to_lower = to_address.lower()

            # --------------------------------------------------------------
            # Sender
            # --------------------------------------------------------------

            if from_lower != ZERO_ADDRESS.lower():
                balances[from_lower] = (
                    balances.get(from_lower, 0)
                    - amount
                )

            # --------------------------------------------------------------
            # Receiver
            # --------------------------------------------------------------

            if (
                to_lower != ZERO_ADDRESS.lower()
                and to_lower != DEAD_ADDRESS.lower()
            ):
                balances[to_lower] = (
                    balances.get(to_lower, 0)
                    + amount
                )

        return balances

    # =========================================================================
    # Holder normalization
    # =========================================================================

    def _build_holders(
        self,
        *,
        balances_raw: dict[str, int],
        decimals: int,
    ) -> list[HolderBalance]:
        """
        Convert reconstructed positive balances into normalized holders.
        """

        holders: list[HolderBalance] = []

        divisor = Decimal("10") ** decimals

        for address, balance_raw in balances_raw.items():

            if balance_raw <= 0:
                continue

            checksum_address = self.web3.to_checksum_address(
                address
            )

            balance = (
                Decimal(balance_raw)
                / divisor
            )

            holders.append(
                HolderBalance(
                    address=checksum_address,
                    balance_raw=balance_raw,
                    balance=balance,
                )
            )

        holders.sort(
            key=lambda holder: (
                holder.balance_raw,
                holder.address.lower(),
            ),
            reverse=True,
        )

        return holders

    # =========================================================================
    # Distribution calculations
    # =========================================================================

    @staticmethod
    def _calculate_top_10_percentage(
        *,
        holders: list[HolderBalance],
        total_balance: Decimal,
    ) -> Decimal | None:
        """
        Calculate the percentage of observed balance held by top 10 holders.
        """

        if total_balance <= 0:
            return None

        top_10_balance = sum(
            (
                holder.balance
                for holder in holders[:10]
            ),
            Decimal("0"),
        )

        percentage = (
            top_10_balance
            / total_balance
            * Decimal("100")
        )

        return percentage.quantize(
            Decimal("0.01")
        )

    # =========================================================================
    # Transfer parsing
    # =========================================================================

    def _parse_transfer_log(
        self,
        log: Any,
    ) -> tuple[str, str, int] | None:
        """
        Parse an ERC-20 Transfer event.
        """

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
        Decode the uint256 Transfer amount.
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

    # =========================================================================
    # Ordering
    # =========================================================================

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

    # =========================================================================
    # Block handling
    # =========================================================================

    @staticmethod
    def _validate_block_range(
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
            raise HolderRPCError(
                "Unable to retrieve latest block."
            ) from exc

        except Exception as exc:
            raise HolderRPCError(
                "Unexpected error retrieving latest block."
            ) from exc

    # =========================================================================
    # Address validation
    # =========================================================================

    def _validate_address(
        self,
        address: str,
    ) -> str:
        """
        Validate and checksum an EVM address.
        """

        if not isinstance(
            address,
            str,
        ):
            raise InvalidHolderAddressError(
                "Address must be a string."
            )

        address = address.strip()

        if not address:
            raise InvalidHolderAddressError(
                "Address is required."
            )

        if not self.web3.is_address(
            address
        ):
            raise InvalidHolderAddressError(
                f"Invalid EVM address: {address}"
            )

        return self.web3.to_checksum_address(
            address
        )
"""
HappyWallet Token Scanner - Production EVM Token Discovery.

This module performs READ-ONLY discovery of ERC-20-like token contracts
from public EVM blockchain state.

Security guarantees
-------------------
- No private keys.
- No seed phrases.
- No transaction signing.
- No transaction submission.
- No token approvals.
- No swaps.
- No automatic buying or selling.
- No fabricated token metrics.

Discovery is intentionally bounded.

Ethereum JSON-RPC does not provide a native API for enumerating every
ERC-20 contract. This service therefore uses ERC-20 Transfer events as
candidate signals and validates the emitting contracts through the
existing EVMContractAnalyzer.

Important semantic limitation
------------------------------
A Transfer event proves that a contract emitted a Transfer event in the
scanned block range. It does NOT prove that the contract was deployed in
that block.

Therefore this service uses terms such as:

    discovered
    observed
    candidate

and deliberately does not describe the observation block as the
contract's deployment block.

Discovery does NOT establish:

- liquidity
- market capitalization
- trading volume
- holder concentration
- liquidity locks
- profitability
- token safety

Those properties belong to subsequent analysis stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from web3 import Web3
from web3.exceptions import Web3Exception

from .contract import ContractAnalysis, EVMContractAnalyzer


# ============================================================================
# Constants
# ============================================================================

TRANSFER_EVENT_SIGNATURE = "Transfer(address,address,uint256)"

TRANSFER_EVENT_TOPIC = Web3.keccak(
    text=TRANSFER_EVENT_SIGNATURE
).hex()

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_LOG_CHUNK_SIZE = 2_000
DEFAULT_MAX_BLOCKS = 100
DEFAULT_MAX_CANDIDATES = 100

MIN_TIMEOUT_SECONDS = 0.1
MIN_LOG_CHUNK_SIZE = 1
MIN_MAX_BLOCKS = 1
MIN_MAX_CANDIDATES = 1


# ============================================================================
# Exceptions
# ============================================================================


class TokenDiscoveryError(Exception):
    """Base exception for token discovery."""


class TokenDiscoveryConfigurationError(TokenDiscoveryError):
    """Raised when discovery configuration is invalid."""


class TokenDiscoveryRPCError(TokenDiscoveryError):
    """Raised when an Ethereum RPC operation fails."""


# ============================================================================
# Data structures
# ============================================================================


@dataclass(frozen=True)
class TokenCandidate:
    """
    A token candidate discovered from actual blockchain state.

    The candidate is created only after the emitting contract has been
    inspected by EVMContractAnalyzer.

    No financial metrics are stored here.
    """

    address: str
    block_number: int
    transaction_hash: str
    contract: ContractAnalysis

    @property
    def name(self) -> str:
        """Return the token contract name."""
        return self.contract.name

    @property
    def symbol(self) -> str:
        """Return the token contract symbol."""
        return self.contract.symbol

    @property
    def decimals(self) -> int | None:
        """Return token decimals when actually available."""
        return self.contract.decimals

    @property
    def is_erc20_like(self) -> bool:
        """Return whether the contract passed ERC-20-like analysis."""
        return self.contract.is_erc20_like


@dataclass(frozen=True)
class TokenDiscoveryResult:
    """
    Immutable result of one bounded discovery operation.

    Metrics
    -------

    transfer_logs_examined:
        Number of raw Transfer logs returned by the RPC.

    unique_contracts_observed:
        Number of unique emitting contract addresses discovered from
        those logs.

    contracts_examined:
        Number of unique contract addresses actually passed to the
        contract analyzer.

    candidate_count:
        Number of contracts that passed ERC-20-like validation.

    complete:
        False because a bounded block scan cannot represent the entire
        Ethereum token universe.
    """

    from_block: int
    to_block: int

    candidates: tuple[TokenCandidate, ...] = field(
        default_factory=tuple
    )

    transfer_logs_examined: int = 0
    unique_contracts_observed: int = 0
    contracts_examined: int = 0

    complete: bool = False

    warnings: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def candidate_count(self) -> int:
        """Return the number of validated token candidates."""
        return len(self.candidates)

    @property
    def block_count(self) -> int:
        """Return the number of blocks included in the scan."""
        return self.to_block - self.from_block + 1


@dataclass(frozen=True)
class _CandidateObservation:
    """
    Internal representation of the earliest observed Transfer event
    for a contract.
    """

    address: str
    block_number: int
    transaction_hash: str


# ============================================================================
# Discovery service
# ============================================================================


class EthereumTokenDiscovery:
    """
    Production-oriented bounded Ethereum token discovery service.

    Discovery strategy
    ------------------

    1. Connect to the configured Ethereum RPC.
    2. Scan a bounded block range for ERC-20 Transfer events.
    3. Count every raw Transfer log returned by the RPC.
    4. Deduplicate emitting contract addresses.
    5. Preserve the earliest observed block/transaction for each address.
    6. Analyze a bounded number of unique contracts.
    7. Return only contracts confirmed as ERC-20-like.

    Security
    --------

    This service is strictly read-only.

    It never:

    - accesses private keys
    - accesses seed phrases
    - signs transactions
    - submits transactions
    - approves token spending
    - executes swaps
    - buys tokens
    - sells tokens
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        log_chunk_size: int = DEFAULT_LOG_CHUNK_SIZE,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
    ) -> None:
        """
        Initialize the Ethereum discovery service.

        Parameters
        ----------
        rpc_url:
            Ethereum JSON-RPC endpoint.

        timeout:
            HTTP request timeout in seconds.

        log_chunk_size:
            Maximum number of blocks requested in one get_logs call.

        max_blocks:
            Maximum total number of blocks allowed in one discovery call.

        max_candidates:
            Maximum number of unique contracts sent to the contract
            analyzer.
        """

        self._validate_configuration(
            rpc_url=rpc_url,
            timeout=timeout,
            log_chunk_size=log_chunk_size,
            max_blocks=max_blocks,
            max_candidates=max_candidates,
        )

        self.rpc_url = rpc_url.strip()
        self.timeout = float(timeout)
        self.log_chunk_size = int(log_chunk_size)
        self.max_blocks = int(max_blocks)
        self.max_candidates = int(max_candidates)

        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={
                    "timeout": self.timeout,
                },
            )
        )

        self.contract_analyzer = EVMContractAnalyzer(
            self.rpc_url,
            timeout=self.timeout,
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def latest_block(self) -> int:
        """
        Return the latest block reported by the configured RPC.

        Raises
        ------
        TokenDiscoveryRPCError
            If the RPC cannot provide the latest block.
        """

        self._ensure_connection()

        try:
            return int(self.web3.eth.block_number)

        except Web3Exception as exc:
            raise TokenDiscoveryRPCError(
                "Unable to retrieve the latest Ethereum block."
            ) from exc

        except Exception as exc:
            raise TokenDiscoveryRPCError(
                "Unexpected error retrieving the latest Ethereum block."
            ) from exc

    def discover(
        self,
        *,
        from_block: int,
        to_block: int | None = None,
    ) -> TokenDiscoveryResult:
        """
        Discover ERC-20-like token contracts from a bounded block range.

        Parameters
        ----------
        from_block:
            First block to inspect, inclusive.

        to_block:
            Last block to inspect, inclusive.

            When omitted, the latest RPC block is used.

        Returns
        -------
        TokenDiscoveryResult
            Immutable discovery result.

        Important
        ---------
        ``complete`` is always False.

        A bounded block scan cannot be represented as a complete
        Ethereum-wide token inventory.
        """

        self._ensure_connection()

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
        )

        observations, transfer_logs_examined = (
            self._discover_candidates(
                from_block=start,
                to_block=end,
            )
        )

        candidates: list[TokenCandidate] = []
        warnings: list[str] = []

        contracts_examined = 0

        for observation in observations:
            if len(candidates) >= self.max_candidates:
                break

            contracts_examined += 1

            try:
                analysis = self.contract_analyzer.analyze(
                    observation.address,
                )

            except Exception as exc:
                warnings.append(
                    "Contract analysis failed for "
                    f"{observation.address}: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue

            if not analysis.is_contract:
                continue

            if not analysis.is_erc20_like:
                continue

            candidates.append(
                TokenCandidate(
                    address=observation.address,
                    block_number=observation.block_number,
                    transaction_hash=observation.transaction_hash,
                    contract=analysis,
                )
            )

        if len(candidates) >= self.max_candidates:
            warnings.append(
                "Candidate analysis limit reached: "
                f"max_candidates={self.max_candidates}."
            )

        return TokenDiscoveryResult(
            from_block=start,
            to_block=end,
            candidates=tuple(candidates),
            transfer_logs_examined=transfer_logs_examined,
            unique_contracts_observed=len(observations),
            contracts_examined=contracts_examined,
            complete=False,
            warnings=tuple(
                dict.fromkeys(warnings)
            ),
        )

    # =========================================================================
    # Candidate discovery
    # =========================================================================

    def _discover_candidates(
        self,
        *,
        from_block: int,
        to_block: int,
    ) -> tuple[tuple[_CandidateObservation, ...], int]:
        """
        Discover and deduplicate Transfer-event emitters.

        Returns
        -------
        tuple
            (
                ordered candidate observations,
                number of raw Transfer logs examined
            )

        Important
        ---------
        This method scans the complete requested block range.

        ``max_candidates`` does NOT stop blockchain log discovery.

        This prevents a large number of non-token or irrelevant contracts
        appearing early in the range from preventing later contracts from
        being observed.
        """

        observations: dict[str, _CandidateObservation] = {}

        transfer_logs_examined = 0

        start = from_block

        while start <= to_block:
            end = min(
                start + self.log_chunk_size - 1,
                to_block,
            )

            logs = self._get_transfer_logs(
                from_block=start,
                to_block=end,
            )

            transfer_logs_examined += len(logs)

            for log in logs:
                observation = self._observation_from_log(
                    log
                )

                if observation is None:
                    continue

                existing = observations.get(
                    observation.address
                )

                if existing is None:
                    observations[
                        observation.address
                    ] = observation

                elif self._observation_key(
                    observation
                ) < self._observation_key(existing):
                    observations[
                        observation.address
                    ] = observation

            start = end + 1

        ordered = tuple(
            sorted(
                observations.values(),
                key=self._observation_key,
            )
        )

        return ordered, transfer_logs_examined

    def _get_transfer_logs(
        self,
        *,
        from_block: int,
        to_block: int,
    ) -> list[Any]:
        """
        Retrieve Transfer logs for one bounded block chunk.

        Raises
        ------
        TokenDiscoveryRPCError
            When the RPC request fails.
        """

        try:
            logs = self.web3.eth.get_logs(
                {
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "topics": [
                        TRANSFER_EVENT_TOPIC
                    ],
                }
            )

            return list(logs)

        except Web3Exception as exc:
            raise TokenDiscoveryRPCError(
                "Ethereum RPC failed while reading "
                "Transfer logs for blocks "
                f"{from_block}-{to_block}."
            ) from exc

        except Exception as exc:
            raise TokenDiscoveryRPCError(
                "Unexpected error while reading "
                "Transfer logs for blocks "
                f"{from_block}-{to_block}."
            ) from exc

    # =========================================================================
    # Log parsing
    # =========================================================================

    def _observation_from_log(
        self,
        log: Any,
    ) -> _CandidateObservation | None:
        """
        Convert an RPC log into an internal candidate observation.

        Invalid or incomplete logs are ignored rather than being allowed
        to create invalid candidate records.
        """

        if not hasattr(log, "get"):
            return None

        address = self._normalize_address(
            log.get("address")
        )

        if address is None:
            return None

        block_number = self._extract_block_number(
            log.get("blockNumber")
        )

        if block_number is None:
            return None

        transaction_hash = self._normalize_transaction_hash(
            log.get("transactionHash")
        )

        if transaction_hash is None:
            return None

        return _CandidateObservation(
            address=address,
            block_number=block_number,
            transaction_hash=transaction_hash,
        )

    @staticmethod
    def _observation_key(
        observation: _CandidateObservation,
    ) -> tuple[int, str, str]:
        """
        Return a stable ordering key.

        Ordering priority:

        1. earliest observed block
        2. transaction hash
        3. contract address
        """

        return (
            observation.block_number,
            observation.transaction_hash,
            observation.address,
        )

    # =========================================================================
    # Connection
    # =========================================================================

    def _ensure_connection(self) -> None:
        """
        Ensure the configured Ethereum RPC endpoint is reachable.
        """

        try:
            if not self.web3.is_connected():
                raise TokenDiscoveryRPCError(
                    "Ethereum RPC endpoint is not connected."
                )

        except TokenDiscoveryRPCError:
            raise

        except Exception as exc:
            raise TokenDiscoveryRPCError(
                "Unable to connect to the Ethereum RPC endpoint."
            ) from exc

    # =========================================================================
    # Configuration validation
    # =========================================================================

    @staticmethod
    def _validate_configuration(
        *,
        rpc_url: str,
        timeout: float,
        log_chunk_size: int,
        max_blocks: int,
        max_candidates: int,
    ) -> None:
        """
        Validate discovery service configuration.
        """

        if not isinstance(rpc_url, str) or not rpc_url.strip():
            raise TokenDiscoveryConfigurationError(
                "rpc_url must be a non-empty string."
            )

        if isinstance(timeout, bool):
            raise TokenDiscoveryConfigurationError(
                "timeout must be a positive number."
            )

        try:
            timeout_value = float(timeout)
        except (TypeError, ValueError):
            raise TokenDiscoveryConfigurationError(
                "timeout must be a positive number."
            )

        if timeout_value < MIN_TIMEOUT_SECONDS:
            raise TokenDiscoveryConfigurationError(
                f"timeout must be >= {MIN_TIMEOUT_SECONDS}."
            )

        if isinstance(log_chunk_size, bool):
            raise TokenDiscoveryConfigurationError(
                "log_chunk_size must be an integer."
            )

        if not isinstance(log_chunk_size, int):
            raise TokenDiscoveryConfigurationError(
                "log_chunk_size must be an integer."
            )

        if log_chunk_size < MIN_LOG_CHUNK_SIZE:
            raise TokenDiscoveryConfigurationError(
                "log_chunk_size must be at least 1."
            )

        if isinstance(max_blocks, bool):
            raise TokenDiscoveryConfigurationError(
                "max_blocks must be an integer."
            )

        if not isinstance(max_blocks, int):
            raise TokenDiscoveryConfigurationError(
                "max_blocks must be an integer."
            )

        if max_blocks < MIN_MAX_BLOCKS:
            raise TokenDiscoveryConfigurationError(
                "max_blocks must be at least 1."
            )

        if isinstance(max_candidates, bool):
            raise TokenDiscoveryConfigurationError(
                "max_candidates must be an integer."
            )

        if not isinstance(max_candidates, int):
            raise TokenDiscoveryConfigurationError(
                "max_candidates must be an integer."
            )

        if max_candidates < MIN_MAX_CANDIDATES:
            raise TokenDiscoveryConfigurationError(
                "max_candidates must be at least 1."
            )

    # =========================================================================
    # Block validation
    # =========================================================================

    def _validate_range(
        self,
        *,
        from_block: int,
        to_block: int,
    ) -> None:
        """
        Validate the requested block range.
        """

        if from_block > to_block:
            raise ValueError(
                "from_block must be less than or equal to to_block."
            )

        block_count = (
            to_block - from_block + 1
        )

        if block_count > self.max_blocks:
            raise ValueError(
                "Discovery range contains "
                f"{block_count} blocks, exceeding "
                f"max_blocks={self.max_blocks}."
            )

    @staticmethod
    def _validate_block_number(
        value: int,
        *,
        field_name: str,
    ) -> int:
        """
        Validate an Ethereum block number.
        """

        if isinstance(value, bool):
            raise ValueError(
                f"{field_name} must be a non-negative integer."
            )

        if not isinstance(value, int):
            raise ValueError(
                f"{field_name} must be a non-negative integer."
            )

        if value < 0:
            raise ValueError(
                f"{field_name} must be a non-negative integer."
            )

        return value

    # =========================================================================
    # Value normalization
    # =========================================================================

    @staticmethod
    def _extract_block_number(
        value: Any,
    ) -> int | None:
        """
        Convert an RPC block-number value into a validated integer.
        """

        if value is None:
            return None

        if isinstance(value, bool):
            return None

        try:
            number = int(value)

        except (TypeError, ValueError):
            return None

        if number < 0:
            return None

        return number

    @staticmethod
    def _normalize_address(
        value: Any,
    ) -> str | None:
        """
        Normalize an Ethereum address to checksum format.
        """

        if value is None:
            return None

        if isinstance(value, bytes):
            if len(value) != 20:
                return None

            value = "0x" + value.hex()

        if not isinstance(value, str):
            return None

        if not Web3.is_address(value):
            return None

        try:
            return Web3.to_checksum_address(value)

        except ValueError:
            return None

    @staticmethod
    def _normalize_transaction_hash(
        value: Any,
    ) -> str | None:
        """
        Normalize an Ethereum transaction hash.

        Supports bytes, hex-capable Web3 values, and strings.
        """

        if value is None:
            return None

        if isinstance(value, bytes):
            return "0x" + value.hex()

        if hasattr(value, "hex"):
            try:
                result = value.hex()

                if isinstance(result, str):
                    return (
                        result
                        if result.startswith("0x")
                        else f"0x{result}"
                    )

            except Exception:
                return None

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return None

            return (
                value
                if value.startswith("0x")
                else f"0x{value}"
            )

        return None
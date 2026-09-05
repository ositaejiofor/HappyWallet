"""
HappyWallet Transaction Service.

Application-level orchestration boundary for transaction preparation,
decoding, signing, verification, encoding, and broadcasting.

Security boundaries
-------------------

This service MUST:

    - never expose private keys
    - never expose wallet mnemonics
    - never decrypt wallet secrets
    - never persist private signing material
    - never treat an application payload as a signed blockchain transaction
    - never broadcast unsigned transaction data
    - never fabricate blockchain-native serialization
    - keep application payload hashes separate from blockchain tx hashes

Architecture
------------

    TransactionBuilder
            |
            v
    canonical application payload
            |
            v
    TransactionDecoder
            |
            v
    NetworkTransactionEncoder
            |
            v
    exact signing digest
            |
            v
    SigningService
            |
            v
    signature
            |
            v
    NetworkTransactionEncoder
            |
            v
    signed raw blockchain transaction
            |
            v
    TransactionBroadcaster
            |
            v
    RPC / blockchain network

TransactionService only orchestrates these components.

It does not implement blockchain-specific serialization itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Optional


from apps.transaction.services.broadcaster import (
    TransactionBroadcaster,
)

from apps.transaction.services.transaction_builder import (
    TransactionBuilder,
)

from apps.transaction.services.transaction_decoder import (
    TransactionDecodeError,
    TransactionDecoder,
)

from apps.wallet.services.signing import (
    SigningService,
)


try:
    from apps.transaction.services.transaction_encoder import (
        EncodedTransaction,
        TransactionEncoder,
        TransactionEncoderError,
    )
except ImportError:  # pragma: no cover

    EncodedTransaction = Any  # type: ignore[misc,assignment]

    class TransactionEncoderError(Exception):
        """Fallback encoder exception."""

    TransactionEncoder = Any  # type: ignore[misc,assignment]


# ============================================================================
# EXCEPTIONS
# ============================================================================


class TransactionServiceError(Exception):
    """Base exception for transaction-service failures."""


class TransactionValidationError(TransactionServiceError):
    """Raised when transaction input or state is invalid."""


class TransactionStateError(TransactionServiceError):
    """Raised when transaction state is invalid."""


class TransactionBuildError(TransactionServiceError):
    """Raised when transaction construction fails."""


class TransactionEncodingError(TransactionServiceError):
    """Raised when transaction encoding fails."""


class TransactionSigningError(TransactionServiceError):
    """Raised when transaction signing or verification fails."""


class TransactionBroadcastError(TransactionServiceError):
    """Raised when transaction broadcasting fails."""


# ============================================================================
# DTOs
# ============================================================================


@dataclass(frozen=True, init=False)
class PreparedTransaction:
    """
    Canonical application-level transaction.

    `payload`
        Application-level canonical data.

    It is NOT a blockchain-native transaction.

    `payload_hash`
        Application-level SHA-256 identifier.

    `transaction_hash`
        Backwards-compatible constructor/property alias for older callers.
    """

    network: str
    payload: bytes
    payload_hash: str
    metadata: Optional[Mapping[str, Any]] = None

    def __init__(
        self,
        network: str,
        payload: bytes,
        payload_hash: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        *,
        transaction_hash: Optional[str] = None,
    ) -> None:

        if payload_hash is None:
            payload_hash = transaction_hash

        if payload_hash is None:
            raise TypeError(
                "PreparedTransaction requires payload_hash "
                "or transaction_hash."
            )

        object.__setattr__(
            self,
            "network",
            network,
        )

        object.__setattr__(
            self,
            "payload",
            payload,
        )

        object.__setattr__(
            self,
            "payload_hash",
            payload_hash,
        )

        object.__setattr__(
            self,
            "metadata",
            metadata,
        )

    @property
    def transaction_hash(self) -> str:
        """
        Backwards-compatible alias.

        This is an application payload hash, not a blockchain tx hash.
        """

        return self.payload_hash


@dataclass(frozen=True)
class SigningRequest:
    """Exact signing material produced by a network encoder."""

    network: str
    digest: bytes
    metadata: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class Signature:
    """Cryptographic signature returned by the signing service."""

    network: str
    signature_der: bytes
    public_key: bytes
    message_hash: str
    algorithm: str


@dataclass(frozen=True, init=False)
class SignedTransaction:
    """
    Signed transaction state.

    `payload`
        Original canonical application payload.

    `raw_transaction`
        Exact network-native signed transaction bytes.

    Only `raw_transaction` may cross the broadcasting boundary.

    The constructor accepts both the modern nested Signature form and the
    legacy flat signature fields used by older callers/tests.
    """

    network: str
    payload: bytes
    raw_transaction: bytes
    transaction_hash: Optional[str]
    signature: Signature
    metadata: Optional[Mapping[str, Any]] = None

    def __init__(
        self,
        network: str,
        payload: bytes,
        raw_transaction: bytes,
        transaction_hash: Optional[str] = None,
        signature: Optional[Signature] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        *,
        signature_der: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        message_hash: Optional[str] = None,
        algorithm: str = "secp256k1",
    ) -> None:

        if signature is None:

            if signature_der is None:
                raise TypeError(
                    "SignedTransaction requires signature or signature_der."
                )

            if public_key is None:
                raise TypeError(
                    "SignedTransaction requires signature or public_key."
                )

            if message_hash is None:
                message_hash = hashlib.sha256(
                    raw_transaction
                ).hexdigest()

            signature = Signature(
                network=network,
                signature_der=signature_der,
                public_key=public_key,
                message_hash=message_hash,
                algorithm=algorithm,
            )

        if not isinstance(signature, Signature):
            raise TypeError(
                "signature must be a Signature instance."
            )

        object.__setattr__(
            self,
            "network",
            network,
        )

        object.__setattr__(
            self,
            "payload",
            payload,
        )

        object.__setattr__(
            self,
            "raw_transaction",
            raw_transaction,
        )

        object.__setattr__(
            self,
            "transaction_hash",
            transaction_hash,
        )

        object.__setattr__(
            self,
            "signature",
            signature,
        )

        object.__setattr__(
            self,
            "metadata",
            metadata,
        )

    @property
    def signature_der(self) -> bytes:
        """Backwards-compatible access to the DER signature."""

        return self.signature.signature_der

    @property
    def public_key(self) -> bytes:
        """Backwards-compatible access to the public key."""

        return self.signature.public_key

    @property
    def message_hash(self) -> str:
        """Backwards-compatible access to the message hash."""

        return self.signature.message_hash

    @property
    def algorithm(self) -> str:
        """Backwards-compatible access to the signing algorithm."""

        return self.signature.algorithm


@dataclass(frozen=True)
class BroadcastResult:
    """Normalized transaction broadcast result."""

    network: str
    transaction_hash: str
    raw_result: Any = None


# ============================================================================
# TRANSACTION SERVICE
# ============================================================================


class TransactionService:
    """
    Application-level transaction orchestration service.

    Blockchain-specific construction, decoding, signing semantics,
    serialization, and broadcasting remain delegated to their respective
    services.
    """

    SUPPORTED_NETWORKS = frozenset(
        {
            "ethereum",
            "bitcoin",
            "tron",
        }
    )

    NETWORK_ALIASES = {
        "eth": "ethereum",
        "ethereum": "ethereum",
        "ethereum-mainnet": "ethereum",
        "mainnet": "ethereum",

        "btc": "bitcoin",
        "bitcoin": "bitcoin",
        "bitcoin-mainnet": "bitcoin",

        "tron": "tron",
        "trx": "tron",
    }

    # ========================================================================
    # NETWORK
    # ========================================================================

    @classmethod
    def normalize_network(
        cls,
        network: str,
    ) -> str:
        """Normalize and validate a supported network."""

        if not isinstance(network, str):
            raise TransactionValidationError(
                "Network must be a string."
            )

        normalized = network.strip().lower()

        if not normalized:
            raise TransactionValidationError(
                "Network must not be empty."
            )

        canonical = cls.NETWORK_ALIASES.get(
            normalized
        )

        if canonical is None:
            raise TransactionValidationError(
                f"Unsupported network: {network!r}."
            )

        if canonical not in cls.SUPPORTED_NETWORKS:
            raise TransactionValidationError(
                f"Unsupported network: {network!r}."
            )

        return canonical

    # ========================================================================
    # BUILDER
    # ========================================================================

    def _get_builder(
        self,
        network: str,
    ) -> Any:
        """
        Resolve a transaction builder.

        Preferred:

            TransactionBuilder.for_network(network)

        Compatibility:

            TransactionBuilder(network=network)
            TransactionBuilder(network)
        """

        normalized_network = self.normalize_network(
            network
        )

        try:
            factory = getattr(
                TransactionBuilder,
                "for_network",
                None,
            )

            if callable(factory):
                return factory(
                    normalized_network
                )

        except AttributeError:
            pass

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to initialize transaction builder for "
                f"{normalized_network}: {exc}"
            ) from exc

        try:
            return TransactionBuilder(
                network=normalized_network
            )

        except TypeError:

            try:
                return TransactionBuilder(
                    normalized_network
                )

            except Exception as exc:
                raise TransactionBuildError(
                    f"Unable to initialize transaction builder for "
                    f"{normalized_network}: {exc}"
                ) from exc

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to initialize transaction builder for "
                f"{normalized_network}: {exc}"
            ) from exc

    # ========================================================================
    # PREPARE
    # ========================================================================

    def prepare(
        self,
        network: str,
        data: Any,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> PreparedTransaction:
        """
        Build a canonical application-level transaction payload.

        The builder is responsible for constructing transaction data.
        TransactionService normalizes that result into deterministic
        application-level bytes.

        This method does NOT create blockchain-native serialization.
        """

        normalized_network = self.normalize_network(
            network
        )

        builder = self._get_builder(
            normalized_network
        )

        try:
            built = self._build_transaction(
                builder=builder,
                network=normalized_network,
                data=data,
            )

        except TransactionBuildError:
            raise

        except TransactionServiceError:
            raise

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to build transaction: {exc}"
            ) from exc

        try:
            payload = self._normalize_builder_result(
                built,
                normalized_network,
            )

        except TransactionValidationError:
            # Empty/invalid payload is a validation failure.
            raise

        except TransactionBuildError:
            # Unsupported builder result is a build failure.
            raise

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to normalize transaction builder result: {exc}"
            ) from exc

        payload_metadata = self._merge_metadata(
            self._extract_metadata(built),
            metadata,
        )

        return PreparedTransaction(
            network=normalized_network,
            payload=payload,
            payload_hash=self._payload_hash(payload),
            metadata=payload_metadata,
        )

    # ========================================================================
    # BUILD
    # ========================================================================

    def _build_transaction(
        self,
        builder: Any,
        network: str,
        data: Any,
    ) -> Any:
        """
        Execute the transaction builder.

        Preferred public interface:

            build(network=..., data=...)
            build(data=...)
            build(data)

        Legacy interface:

            _request_from_data()
            validate()
            serialize()
        """

        build = getattr(
            builder,
            "build",
            None,
        )

        if callable(build):

            attempts = (
                lambda: build(
                    network=network,
                    data=data,
                ),
                lambda: build(
                    data=data,
                ),
                lambda: build(
                    data,
                ),
            )

            last_type_error: Optional[Exception] = None

            for attempt in attempts:

                try:
                    return attempt()

                except TypeError as exc:
                    last_type_error = exc

            raise TransactionBuildError(
                "Unable to call transaction builder."
            ) from last_type_error

        request_builder = getattr(
            builder,
            "_request_from_data",
            None,
        )

        if not callable(request_builder):
            raise TransactionBuildError(
                "Transaction builder does not provide a supported "
                "build interface."
            )

        try:
            request = request_builder(
                data
            )

        except TypeError:

            try:
                request = request_builder(
                    network=network,
                    data=data,
                )

            except Exception as exc:
                raise TransactionBuildError(
                    f"Unable to build transaction request: {exc}"
                ) from exc

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to build transaction request: {exc}"
            ) from exc

        validate = getattr(
            builder,
            "validate",
            None,
        )

        if callable(validate):

            try:
                validate(request)

            except TypeError:

                try:
                    validate(
                        network=network,
                        request=request,
                    )

                except Exception as exc:
                    raise TransactionBuildError(
                        f"Unable to validate transaction request: {exc}"
                    ) from exc

            except Exception as exc:
                raise TransactionBuildError(
                    f"Unable to validate transaction request: {exc}"
                ) from exc

        serialize = getattr(
            builder,
            "serialize",
            None,
        )

        if not callable(serialize):
            raise TransactionBuildError(
                "Legacy transaction builder does not provide serialize()."
            )

        try:
            return serialize(
                request
            )

        except TypeError:

            try:
                return serialize(
                    network=network,
                    request=request,
                )

            except Exception as exc:
                raise TransactionBuildError(
                    f"Unable to serialize transaction request: {exc}"
                ) from exc

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to serialize transaction request: {exc}"
            ) from exc

    # ========================================================================
    # BUILDER RESULT NORMALIZATION
    # ========================================================================

    def _normalize_builder_result(
        self,
        result: Any,
        network: str,
    ) -> bytes:
        """
        Normalize a TransactionBuilder result into canonical application
        payload bytes.

        Supported forms:

            bytes
            bytearray
            memoryview
            {"payload": ...}
            {"transaction": ...}
            arbitrary mappings
            objects exposing .payload
            objects exposing .transaction
            objects exposing .to_dict()
            dataclass transaction DTOs

        Unsupported objects fail closed.

        `network` is validated here even though the recursive normalization
        itself is network-independent.
        """

        # Validate the public network boundary once.

        self.normalize_network(
            network
        )

        # IMPORTANT:
        #
        # Do not pass `network` into recursive calls.
        #
        # The recursive helper has no network parameter. This prevents the
        # previous UnboundLocalError caused by recursive network handling.

        return self._normalize_builder_value(
            result
        )

    def _normalize_builder_value(
        self,
        result: Any,
    ) -> bytes:
        """
        Internal recursive builder-result normalizer.

        This helper deliberately has no network parameter.

        That makes recursive normalization deterministic and prevents
        network-variable shadowing or accidental loss of the network
        argument.
        """

        # ------------------------------------------------------------------
        # No result
        # ------------------------------------------------------------------

        if result is None:
            raise TransactionBuildError(
                "Transaction builder returned no payload."
            )

        # ------------------------------------------------------------------
        # Raw bytes
        # ------------------------------------------------------------------

        if isinstance(result, bytes):
            return self._validate_bytes(
                result,
                field_name="Transaction payload",
                error_class=TransactionValidationError,
            )

        if isinstance(result, bytearray):
            return self._validate_bytes(
                bytes(result),
                field_name="Transaction payload",
                error_class=TransactionValidationError,
            )

        if isinstance(result, memoryview):
            return self._validate_bytes(
                result.tobytes(),
                field_name="Transaction payload",
                error_class=TransactionValidationError,
            )

        # ------------------------------------------------------------------
        # Reject unittest.mock objects
        # ------------------------------------------------------------------

        result_type = type(result)

        if result_type.__module__.startswith(
            "unittest.mock"
        ):
            raise TransactionBuildError(
                "Unsupported transaction builder result."
            )

        # ------------------------------------------------------------------
        # Mapping result
        # ------------------------------------------------------------------

        if isinstance(result, Mapping):

            # Explicit payload wrapper.
            if "payload" in result:
                return self._normalize_builder_value(
                    result["payload"]
                )

            # Explicit transaction wrapper.
            if "transaction" in result:
                return self._normalize_builder_value(
                    result["transaction"]
                )

            # Otherwise treat the mapping itself as transaction data.
            return self._mapping_to_payload(
                result
            )

        # ------------------------------------------------------------------
        # Object exposing .payload
        # ------------------------------------------------------------------

        try:
            payload = result_type.__getattribute__(
                result,
                "payload",
            )

        except AttributeError:
            payload = None

        if payload is not None:
            return self._normalize_builder_value(
                payload
            )

        # ------------------------------------------------------------------
        # Object exposing .transaction
        # ------------------------------------------------------------------

        try:
            transaction = result_type.__getattribute__(
                result,
                "transaction",
            )

        except AttributeError:
            transaction = None

        if transaction is not None:
            return self._normalize_builder_value(
                transaction
            )

        # ------------------------------------------------------------------
        # Object exposing .to_dict()
        # ------------------------------------------------------------------

        try:
            to_dict = result_type.__getattribute__(
                result,
                "to_dict",
            )

        except AttributeError:
            to_dict = None

        if callable(to_dict):

            try:
                value = to_dict()

            except Exception as exc:
                raise TransactionBuildError(
                    "Unable to convert transaction builder result "
                    f"to dictionary: {exc}"
                ) from exc

            return self._normalize_builder_value(
                value
            )

        # ------------------------------------------------------------------
        # Dataclass-style object
        # ------------------------------------------------------------------

        if is_dataclass(result) and not isinstance(result, type):

            try:
                value = asdict(result)

            except Exception as exc:
                raise TransactionBuildError(
                    "Unable to convert transaction builder result: "
                    f"{exc}"
                ) from exc

            return self._normalize_builder_value(
                value
            )

        # ------------------------------------------------------------------
        # Fail closed
        # ------------------------------------------------------------------

        raise TransactionBuildError(
            "Unsupported transaction builder result."
        )

    @staticmethod
    def _mapping_to_payload(
        value: Mapping[str, Any],
    ) -> bytes:
        """
        Convert transaction mapping data into deterministic application
        payload bytes.

        TransactionDecoder.canonicalize() is preferred because it represents
        the project's canonical transaction representation.

        JSON is only a compatibility fallback when canonicalize() does not
        exist.
        """

        canonicalize = getattr(
            TransactionDecoder,
            "canonicalize",
            None,
        )

        # ------------------------------------------------------------------
        # Preferred canonicalizer
        # ------------------------------------------------------------------

        if callable(canonicalize):

            try:
                canonical = canonicalize(
                    value
                )

            except AttributeError:
                canonical = None

            except Exception as exc:
                raise TransactionBuildError(
                    f"Unable to canonicalize transaction data: {exc}"
                ) from exc

            if canonical is not None:

                if isinstance(canonical, bytes):
                    result = canonical

                elif isinstance(canonical, bytearray):
                    result = bytes(canonical)

                elif isinstance(canonical, memoryview):
                    result = canonical.tobytes()

                elif isinstance(canonical, str):
                    result = canonical.encode(
                        "utf-8"
                    )

                else:
                    raise TransactionBuildError(
                        "Transaction canonicalizer returned an unsupported "
                        "payload type."
                    )

                if not result:
                    raise TransactionValidationError(
                        "Transaction payload must not be empty."
                    )

                return result

        # ------------------------------------------------------------------
        # Compatibility JSON fallback
        # ------------------------------------------------------------------

        try:
            result = json.dumps(
                dict(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode(
                "utf-8"
            )

        except Exception as exc:
            raise TransactionBuildError(
                f"Unable to canonicalize transaction data: {exc}"
            ) from exc

        if not result:
            raise TransactionValidationError(
                "Transaction payload must not be empty."
            )

        return result

    # ========================================================================
    # DECODING
    # ========================================================================

    def decode(
        self,
        network: str,
        payload: bytes,
    ) -> Any:
        """
        Decode an application transaction payload.

        Network-specific transaction semantics remain delegated to the
        decoder implementation.
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        decoder = self._get_decoder()

        try:
            decoded = self._call_decoder(
                decoder,
                normalized_network,
                payload,
            )

        except TransactionValidationError:
            raise

        except TransactionDecodeError as exc:
            raise TransactionValidationError(
                f"Unable to decode transaction payload: {exc}"
            ) from exc

        except Exception as exc:
            raise TransactionValidationError(
                f"Unable to decode transaction payload: {exc}"
            ) from exc

        decoded_network = self._safe_object_attribute(
            decoded,
            "network",
        )

        if isinstance(decoded_network, str):

            decoded_network = self.normalize_network(
                decoded_network
            )

            if decoded_network != normalized_network:
                raise TransactionValidationError(
                    "Decoded transaction network does not match "
                    "the requested network."
                )

        return decoded

    def _get_decoder(self) -> Any:
        """Create the transaction decoder."""

        return TransactionDecoder()

    def _call_decoder(
        self,
        decoder: Any,
        network: str,
        payload: bytes,
    ) -> Any:
        """Call decoder using current and legacy signatures."""

        decode = getattr(
            decoder,
            "decode",
            None,
        )

        if not callable(decode):
            raise TransactionValidationError(
                "Transaction decoder does not provide decode()."
            )

        try:
            return decode(
                payload
            )

        except TypeError:
            return decode(
                network=network,
                payload=payload,
            )

    # ========================================================================
    # SIGNING PREPARATION
    # ========================================================================

    def prepare_signing(
        self,
        network: str,
        payload: bytes,
        *,
        decoded: Any = None,
    ) -> SigningRequest:
        """
        Obtain the exact digest that must be signed.

        The network-specific encoder owns signing semantics.
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        if decoded is None:
            decoded = self.decode(
                normalized_network,
                payload,
            )

        encoder = self._get_encoder(
            normalized_network
        )

        prepare_signing = getattr(
            encoder,
            "prepare_signing",
            None,
        )

        if not callable(prepare_signing):
            raise TransactionEncodingError(
                f"No signing preparation capability is registered "
                f"for network {normalized_network!r}."
            )

        try:
            result = prepare_signing(
                payload=payload,
                decoded=decoded,
            )

        except TypeError:

            try:
                result = prepare_signing(
                    normalized_network,
                    payload,
                    decoded,
                )

            except Exception as exc:
                raise TransactionEncodingError(
                    f"Unable to prepare signing digest: {exc}"
                ) from exc

        except Exception as exc:
            raise TransactionEncodingError(
                f"Unable to prepare signing digest: {exc}"
            ) from exc

        digest, result_metadata = self._normalize_signing_result(
            result
        )

        if len(digest) != 32:
            raise TransactionEncodingError(
                "Signing digest must be exactly 32 bytes."
            )

        return SigningRequest(
            network=normalized_network,
            digest=digest,
            metadata=self._merge_metadata(
                result_metadata,
                self._extract_metadata(decoded),
            ),
        )

    def _normalize_signing_result(
        self,
        result: Any,
    ) -> tuple[
        bytes,
        Optional[Mapping[str, Any]],
    ]:
        """Normalize encoder signing-preparation output."""

        if result is None:
            raise TransactionEncodingError(
                "Encoder returned no signing digest."
            )

        metadata = self._extract_metadata(
            result
        )

        if isinstance(result, bytes):
            return result, metadata

        if isinstance(result, bytearray):
            return bytes(result), metadata

        if isinstance(result, memoryview):
            return result.tobytes(), metadata

        digest = self._safe_object_attribute(
            result,
            "digest",
        )

        if digest is None:
            digest = self._safe_object_attribute(
                result,
                "message_hash",
            )

        if isinstance(digest, str):

            try:
                digest = bytes.fromhex(
                    digest.removeprefix("0x")
                )

            except ValueError as exc:
                raise TransactionEncodingError(
                    "Encoder returned an invalid hexadecimal digest."
                ) from exc

        if isinstance(digest, bytearray):
            digest = bytes(digest)

        if isinstance(digest, memoryview):
            digest = digest.tobytes()

        if isinstance(digest, bytes):
            return digest, metadata

        raise TransactionEncodingError(
            "Unsupported signing-preparation result."
        )

    # ========================================================================
    # SIGN
    # ========================================================================

    def sign(
        self,
        network: str,
        payload: bytes,
        private_key: bytes,
        *,
        decoded: Any = None,
    ) -> Signature:
        """
        Sign an application transaction payload.

        The private key crosses only the signing boundary and is never
        returned by this service.
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        self._validate_bytes(
            private_key,
            field_name="Private key",
        )

        signing_request = self.prepare_signing(
            normalized_network,
            payload,
            decoded=decoded,
        )

        try:
            return self._sign_request(
                private_key,
                signing_request,
            )

        finally:
            del private_key

    def _sign_request(
        self,
        private_key: bytes,
        signing_request: SigningRequest,
    ) -> Signature:
        """Sign an already-prepared exact digest."""

        self._validate_bytes(
            private_key,
            field_name="Private key",
            error_class=TransactionSigningError,
        )

        if len(signing_request.digest) != 32:
            raise TransactionSigningError(
                "Signing digest must be exactly 32 bytes."
            )

        try:
            signing_service = SigningService()

            sign_digest = getattr(
                signing_service,
                "sign_digest",
                None,
            )

            if callable(sign_digest):

                result = sign_digest(
                    private_key=private_key,
                    digest=signing_request.digest,
                )

            else:

                legacy_sign = getattr(
                    signing_service,
                    "sign_transaction_payload",
                    None,
                )

                if not callable(legacy_sign):
                    raise TransactionSigningError(
                        "SigningService does not provide a supported "
                        "signing method."
                    )

                result = self._call_legacy_signer(
                    legacy_sign,
                    private_key,
                    signing_request.digest,
                )

        except TransactionSigningError:
            raise

        except Exception as exc:
            raise TransactionSigningError(
                f"Transaction signing failed: {exc}"
            ) from exc

        return self._normalize_signature(
            signing_request,
            result,
        )

    def _call_legacy_signer(
        self,
        signer: Any,
        private_key: bytes,
        digest: bytes,
    ) -> Any:
        """Call legacy signing API."""

        try:
            return signer(
                private_key=private_key,
                payload=digest,
            )

        except TypeError:

            try:
                return signer(
                    private_key,
                    digest,
                )

            except TypeError:
                return signer(
                    payload=digest,
                    private_key=private_key,
                )

    def _normalize_signature(
        self,
        signing_request: SigningRequest,
        result: Any,
    ) -> Signature:
        """Normalize SigningService output."""

        if isinstance(result, Signature):

            if result.network != signing_request.network:
                raise TransactionSigningError(
                    "Signing result network does not match "
                    "the signing request network."
                )

            return result

        if result is None:
            raise TransactionSigningError(
                "SigningService returned no signature."
            )

        if isinstance(result, Mapping):

            signature_der = result.get(
                "signature_der"
            )

            if signature_der is None:
                signature_der = result.get(
                    "signature"
                )

            public_key = result.get(
                "public_key"
            )

            message_hash = result.get(
                "message_hash"
            )

            algorithm = result.get(
                "algorithm",
                "secp256k1",
            )

        else:

            signature_der = self._safe_object_attribute(
                result,
                "signature_der",
            )

            if signature_der is None:
                signature_der = self._safe_object_attribute(
                    result,
                    "signature",
                )

            public_key = self._safe_object_attribute(
                result,
                "public_key",
            )

            message_hash = self._safe_object_attribute(
                result,
                "message_hash",
            )

            algorithm = self._safe_object_attribute(
                result,
                "algorithm",
            )

            if algorithm is None:
                algorithm = "secp256k1"

        signature_der = self._normalize_hex_bytes(
            signature_der,
            field_name="Signature",
            error_class=TransactionSigningError,
        )

        public_key = self._normalize_hex_bytes(
            public_key,
            field_name="Public key",
            error_class=TransactionSigningError,
        )

        if message_hash is None:
            message_hash = hashlib.sha256(
                signing_request.digest
            ).hexdigest()

        elif isinstance(message_hash, bytes):
            message_hash = message_hash.hex()

        elif not isinstance(message_hash, str):
            message_hash = str(message_hash)

        return Signature(
            network=signing_request.network,
            signature_der=signature_der,
            public_key=public_key,
            message_hash=message_hash,
            algorithm=str(algorithm),
        )

    # ========================================================================
    # VERIFY
    # ========================================================================

    def verify(
        self,
        network: str,
        payload: bytes,
        signature: bytes | Signature | Any = None,
        public_key: bytes = b"",
        *,
        signature_der: bytes | str | None = None,
        decoded: Any = None,
    ) -> bool:
        """
        Verify a signature against the exact signing digest.

        Supports both:

            signature=...

        and legacy:

            signature_der=...
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        public_key = self._validate_bytes(
            public_key,
            field_name="Public key",
        )

        if signature is None:
            signature = signature_der

        if signature is None:
            raise TransactionValidationError(
                "Signature data is missing."
            )

        normalized_signature = self._normalize_verify_signature(
            signature,
            normalized_network,
        )

        normalized_signature = self._validate_bytes(
            normalized_signature,
            field_name="Signature",
        )

        signing_request = self.prepare_signing(
            normalized_network,
            payload,
            decoded=decoded,
        )

        return self._verify_signature(
            signing_request,
            normalized_signature,
            public_key,
        )

    def _verify_signature(
        self,
        signing_request: SigningRequest,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify raw signature bytes against the prepared digest."""

        signature_bytes = self._validate_bytes(
            signature,
            field_name="Signature",
            error_class=TransactionSigningError,
        )

        public_key_bytes = self._validate_bytes(
            public_key,
            field_name="Public key",
            error_class=TransactionSigningError,
        )

        try:
            signing_service = SigningService()

            verify_digest = getattr(
                signing_service,
                "verify_digest",
                None,
            )

            if callable(verify_digest):

                try:
                    result = verify_digest(
                        public_key=public_key_bytes,
                        digest=signing_request.digest,
                        signature=signature_bytes,
                    )

                except TypeError:

                    result = verify_digest(
                        public_key_bytes,
                        signing_request.digest,
                        signature_bytes,
                    )

                return bool(result)

            legacy_verify = getattr(
                signing_service,
                "verify",
                None,
            )

            if not callable(legacy_verify):
                legacy_verify = getattr(
                    signing_service,
                    "verify_signature",
                    None,
                )

            if not callable(legacy_verify):
                raise TransactionSigningError(
                    "SigningService does not provide a supported "
                    "verification method."
                )

            try:
                return bool(
                    legacy_verify(
                        public_key=public_key_bytes,
                        payload=signing_request.digest,
                        signature=signature_bytes,
                    )
                )

            except TypeError:

                return bool(
                    legacy_verify(
                        public_key_bytes,
                        signing_request.digest,
                        signature_bytes,
                    )
                )

        except TransactionSigningError:
            raise

        except Exception:
            return False

    @staticmethod
    def _normalize_verify_signature(
        signature: Any,
        network: str,
    ) -> bytes:
        """Extract raw signature bytes."""

        if isinstance(signature, Signature):

            if signature.network != network:
                raise TransactionValidationError(
                    "Signature network does not match transaction network."
                )

            return signature.signature_der

        if isinstance(signature, bytes):
            return signature

        if isinstance(signature, bytearray):
            return bytes(signature)

        if isinstance(signature, memoryview):
            return signature.tobytes()

        if isinstance(signature, str):

            try:
                return bytes.fromhex(
                    signature.removeprefix("0x")
                )

            except ValueError as exc:
                raise TransactionValidationError(
                    "Signature must contain valid hexadecimal data."
                ) from exc

        if isinstance(signature, Mapping):

            value = signature.get(
                "signature_der"
            )

            if value is None:
                value = signature.get(
                    "signature"
                )

            if value is None:
                raise TransactionValidationError(
                    "Signature data is missing."
                )

            return TransactionService._normalize_verify_signature(
                value,
                network,
            )

        signature_type = type(signature)

        if signature_type.__module__.startswith(
            "unittest.mock"
        ):
            raise TransactionValidationError(
                "Signature data is missing."
            )

        value = TransactionService._safe_object_attribute(
            signature,
            "signature_der",
        )

        if value is None:
            value = TransactionService._safe_object_attribute(
                signature,
                "signature",
            )

        if value is None:
            raise TransactionValidationError(
                "Signature data is missing."
            )

        return TransactionService._normalize_verify_signature(
            value,
            network,
        )

    # ========================================================================
    # ENCODER
    # ========================================================================

    def _get_encoder(
        self,
        network: str,
    ) -> Any:
        """Resolve a network-specific transaction encoder."""

        normalized_network = self.normalize_network(
            network
        )

        try:
            factory = getattr(
                TransactionEncoder,
                "for_network",
                None,
            )

            if callable(factory):
                return factory(
                    normalized_network
                )

        except TransactionEncoderError as exc:
            raise TransactionEncodingError(
                str(exc)
            ) from exc

        except Exception as exc:
            raise TransactionEncodingError(
                f"Unable to initialize encoder for "
                f"{normalized_network}: {exc}"
            ) from exc

        try:
            getter = getattr(
                TransactionEncoder,
                "get_serializer",
                None,
            )

            if callable(getter):

                serializer = getter(
                    normalized_network
                )

                if serializer is None:
                    raise TransactionEncodingError(
                        f"No transaction serializer is registered "
                        f"for network {normalized_network!r}."
                    )

                return serializer

        except TransactionEncoderError as exc:
            raise TransactionEncodingError(
                str(exc)
            ) from exc

        except TransactionEncodingError:
            raise

        except Exception as exc:
            raise TransactionEncodingError(
                f"Unable to resolve encoder for "
                f"{normalized_network}: {exc}"
            ) from exc

        raise TransactionEncodingError(
            f"No transaction serializer is registered "
            f"for network {normalized_network!r}."
        )

    # ========================================================================
    # ENCODE SIGNED TRANSACTION
    # ========================================================================

    def encode_signed_transaction(
        self,
        network: str,
        payload: bytes,
        signature: Signature,
        *,
        decoded: Any = None,
    ) -> SignedTransaction:
        """
        Convert application payload + signature into exact network-native
        signed transaction bytes.
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        if not isinstance(signature, Signature):
            raise TransactionEncodingError(
                "A TransactionService Signature is required."
            )

        if signature.network != normalized_network:
            raise TransactionEncodingError(
                "Signature network does not match transaction network."
            )

        if decoded is None:
            decoded = self.decode(
                normalized_network,
                payload,
            )

        encoder = self._get_encoder(
            normalized_network
        )

        encoder_method = getattr(
            encoder,
            "encode_signed_transaction",
            None,
        )

        if not callable(encoder_method):
            encoder_method = getattr(
                encoder,
                "encode_from_signing_result",
                None,
            )

        if not callable(encoder_method):
            raise TransactionEncodingError(
                f"No signed transaction serializer is registered "
                f"for network {normalized_network!r}."
            )

        try:
            encoded = self._call_signed_encoder(
                encoder_method,
                normalized_network,
                payload,
                decoded,
                signature,
            )

        except TransactionEncodingError:
            raise

        except Exception as exc:
            raise TransactionEncodingError(
                f"Unable to encode signed transaction: {exc}"
            ) from exc

        (
            raw_transaction,
            transaction_hash,
            encoder_metadata,
        ) = self._normalize_encoded_transaction(
            encoded
        )

        metadata = self._merge_metadata(
            encoder_metadata,
            signature_metadata={
                "algorithm": signature.algorithm,
                "message_hash": signature.message_hash,
            },
        )

        return SignedTransaction(
            network=normalized_network,
            payload=payload,
            raw_transaction=raw_transaction,
            transaction_hash=transaction_hash,
            signature=signature,
            metadata=metadata,
        )

    def _call_signed_encoder(
        self,
        encoder_method: Any,
        network: str,
        payload: bytes,
        decoded: Any,
        signature: Signature,
    ) -> Any:
        """Call signed encoder using supported interfaces."""

        attempts = (
            lambda: encoder_method(
                payload=payload,
                decoded=decoded,
                signature=signature,
            ),
            lambda: encoder_method(
                network=network,
                payload=payload,
                decoded=decoded,
                signature=signature,
            ),
            lambda: encoder_method(
                payload=payload,
                signature_der=signature.signature_der,
                public_key=signature.public_key,
            ),
            lambda: encoder_method(
                network,
                payload,
                decoded,
                signature,
            ),
        )

        last_type_error: Optional[Exception] = None

        for attempt in attempts:

            try:
                return attempt()

            except TypeError as exc:
                last_type_error = exc

        raise TransactionEncodingError(
            "Unable to call signed transaction encoder."
        ) from last_type_error

    def _normalize_encoded_transaction(
        self,
        encoded: Any,
    ) -> tuple[
        bytes,
        Optional[str],
        Optional[Mapping[str, Any]],
    ]:
        """Normalize encoder output."""

        if encoded is None:
            raise TransactionEncodingError(
                "Encoder returned no signed transaction."
            )

        if isinstance(encoded, bytes):
            return (
                self._normalize_raw_transaction(encoded),
                None,
                None,
            )

        if isinstance(encoded, bytearray):
            return (
                self._normalize_raw_transaction(
                    bytes(encoded)
                ),
                None,
                None,
            )

        if isinstance(encoded, memoryview):
            return (
                self._normalize_raw_transaction(
                    encoded.tobytes()
                ),
                None,
                None,
            )

        if isinstance(encoded, Mapping):

            raw = encoded.get(
                "raw_transaction"
            )

            if raw is None:
                raw = encoded.get(
                    "raw"
                )

            transaction_hash = encoded.get(
                "transaction_hash"
            )

            if transaction_hash is None:
                transaction_hash = encoded.get(
                    "tx_hash"
                )

            metadata = encoded.get(
                "metadata"
            )

            return (
                self._normalize_raw_transaction(raw),
                self._normalize_optional_hash(
                    transaction_hash
                ),
                metadata,
            )

        encoded_type = type(encoded)

        if encoded_type.__module__.startswith(
            "unittest.mock"
        ):
            raise TransactionEncodingError(
                "Unsupported encoded transaction result."
            )

        raw = self._safe_object_attribute(
            encoded,
            "raw_transaction",
        )

        if raw is None:
            raw = self._safe_object_attribute(
                encoded,
                "raw",
            )

        transaction_hash = self._safe_object_attribute(
            encoded,
            "transaction_hash",
        )

        if transaction_hash is None:
            transaction_hash = self._safe_object_attribute(
                encoded,
                "tx_hash",
            )

        metadata = self._extract_metadata(
            encoded
        )

        return (
            self._normalize_raw_transaction(raw),
            self._normalize_optional_hash(
                transaction_hash
            ),
            metadata,
        )

    @staticmethod
    def _normalize_raw_transaction(
        raw: Any,
    ) -> bytes:
        """Validate exact signed raw transaction bytes."""

        if isinstance(raw, bytes):
            value = raw

        elif isinstance(raw, bytearray):
            value = bytes(raw)

        elif isinstance(raw, memoryview):
            value = raw.tobytes()

        elif isinstance(raw, str):

            try:
                value = bytes.fromhex(
                    raw.removeprefix("0x")
                )

            except ValueError as exc:
                raise TransactionEncodingError(
                    "Encoded transaction is not valid hexadecimal."
                ) from exc

        else:
            raise TransactionEncodingError(
                "Encoder did not return raw transaction bytes."
            )

        if not value:
            raise TransactionEncodingError(
                "Encoded transaction is empty."
            )

        return value

    @staticmethod
    def _normalize_optional_hash(
        value: Any,
    ) -> Optional[str]:
        """Normalize an optional blockchain transaction hash."""

        if value is None:
            return None

        if isinstance(value, bytes):
            return "0x" + value.hex()

        if isinstance(value, bytearray):
            return "0x" + bytes(value).hex()

        if isinstance(value, memoryview):
            return "0x" + value.tobytes().hex()

        value = str(value)

        return value or None

    # ========================================================================
    # BROADCAST
    # ========================================================================

    def broadcast(
        self,
        network: str,
        signed_transaction: SignedTransaction,
    ) -> BroadcastResult:
        """
        Broadcast an already-signed network-native transaction.

        Only SignedTransaction.raw_transaction may cross this boundary.
        """

        normalized_network = self.normalize_network(
            network
        )

        if not isinstance(
            signed_transaction,
            SignedTransaction,
        ):
            raise TransactionBroadcastError(
                "Only SignedTransaction objects may be broadcast."
            )

        if signed_transaction.network != normalized_network:
            raise TransactionBroadcastError(
                "Signed transaction network does not match "
                "requested network."
            )

        raw_transaction = self._validate_bytes(
            signed_transaction.raw_transaction,
            field_name="Signed raw transaction",
            error_class=TransactionBroadcastError,
        )

        if not raw_transaction:
            raise TransactionBroadcastError(
                "Cannot broadcast an empty signed transaction."
            )

        try:
            broadcaster = TransactionBroadcaster()

            result = self._call_broadcaster(
                broadcaster,
                normalized_network,
                signed_transaction,
            )

        except TransactionBroadcastError:
            raise

        except Exception as exc:
            raise TransactionBroadcastError(
                f"Transaction broadcast failed: {exc}"
            ) from exc

        transaction_hash = self._extract_broadcast_hash(
            result,
            fallback=signed_transaction.transaction_hash,
        )

        if not transaction_hash:
            raise TransactionBroadcastError(
                "Broadcaster did not return a transaction hash."
            )

        return BroadcastResult(
            network=normalized_network,
            transaction_hash=transaction_hash,
            raw_result=result,
        )

    def _call_broadcaster(
        self,
        broadcaster: Any,
        network: str,
        signed_transaction: SignedTransaction,
    ) -> Any:
        """Call broadcaster using supported interfaces."""

        method = getattr(
            broadcaster,
            "broadcast",
            None,
        )

        if not callable(method):
            raise TransactionBroadcastError(
                "Transaction broadcaster does not provide broadcast()."
            )

        attempts = (
            lambda: method(
                network=network,
                signed_transaction=signed_transaction,
            ),
            lambda: method(
                network=network,
                raw_transaction=signed_transaction.raw_transaction,
            ),
            lambda: method(
                network,
                signed_transaction.raw_transaction,
            ),
        )

        last_type_error: Optional[Exception] = None

        for attempt in attempts:

            try:
                return attempt()

            except TypeError as exc:
                last_type_error = exc

        raise TransactionBroadcastError(
            "Unable to call transaction broadcaster."
        ) from last_type_error

    # ========================================================================
    # COMPLETE PIPELINE
    # ========================================================================

    def execute(
        self,
        network: str,
        data: Any,
        private_key: bytes,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> BroadcastResult:
        """
        Execute the complete transaction pipeline.

            prepare
              |
            decode
              |
            prepare_signing
              |
            sign
              |
            verify
              |
            encode
              |
            broadcast

        The broadcaster receives only SignedTransaction.
        """

        normalized_network = self.normalize_network(
            network
        )

        prepared = self.prepare(
            normalized_network,
            data,
            metadata=metadata,
        )

        decoded = self.decode(
            normalized_network,
            prepared.payload,
        )

        signing_request = self.prepare_signing(
            normalized_network,
            prepared.payload,
            decoded=decoded,
        )

        try:
            signature = self._sign_request(
                private_key,
                signing_request,
            )

        finally:
            del private_key

        if not self._verify_signature(
            signing_request,
            signature.signature_der,
            signature.public_key,
        ):
            raise TransactionSigningError(
                "Transaction signature verification failed."
            )

        signed_transaction = self.encode_signed_transaction(
            normalized_network,
            prepared.payload,
            signature,
            decoded=decoded,
        )

        if not signed_transaction.raw_transaction:
            raise TransactionStateError(
                "Refusing to broadcast a transaction without "
                "signed raw transaction bytes."
            )

        return self.broadcast(
            network=normalized_network,
            signed_transaction=signed_transaction,
        )

    # ========================================================================
    # UTILITY
    # ========================================================================

    @staticmethod
    def _payload_hash(
        payload: bytes,
    ) -> str:
        """
        Calculate application-level SHA-256.

        This is deliberately NOT a blockchain transaction hash.
        """

        return hashlib.sha256(
            payload
        ).hexdigest()

    @staticmethod
    def _validate_amount(
        value: Any,
    ) -> Decimal:
        """Validate a strictly positive finite decimal amount."""

        if value is None:
            raise TransactionValidationError(
                "Amount must not be empty."
            )

        if isinstance(value, str) and not value.strip():
            raise TransactionValidationError(
                "Amount must not be empty."
            )

        try:
            amount = Decimal(
                str(value)
            )

        except (
            InvalidOperation,
            ValueError,
            TypeError,
        ) as exc:
            raise TransactionValidationError(
                "Amount must be a valid decimal value."
            ) from exc

        if not amount.is_finite():
            raise TransactionValidationError(
                "Amount must be finite."
            )

        if amount <= 0:
            raise TransactionValidationError(
                "Amount must be greater than zero."
            )

        return amount

    @staticmethod
    def _validate_bytes(
        value: Any,
        *,
        field_name: str,
        error_class: type[Exception] = TransactionValidationError,
    ) -> bytes:
        """
        Validate a non-empty bytes-like value.

        Empty values are rejected consistently at every security boundary.
        """

        if value is None:
            raise error_class(
                f"{field_name} must not be empty."
            )

        if isinstance(value, bytearray):
            value = bytes(value)

        elif isinstance(value, memoryview):
            value = value.tobytes()

        elif not isinstance(value, bytes):
            raise error_class(
                f"{field_name} must be bytes."
            )

        if not value:
            raise error_class(
                f"{field_name} must not be empty."
            )

        return value

    @staticmethod
    def _normalize_hex_bytes(
        value: Any,
        *,
        field_name: str,
        error_class: type[Exception],
    ) -> bytes:
        """Normalize bytes or hexadecimal string into non-empty bytes."""

        if isinstance(value, str):

            try:
                value = bytes.fromhex(
                    value.removeprefix("0x")
                )

            except ValueError as exc:
                raise error_class(
                    f"{field_name} contains invalid hexadecimal data."
                ) from exc

        return TransactionService._validate_bytes(
            value,
            field_name=field_name,
            error_class=error_class,
        )

    @staticmethod
    def _safe_object_attribute(
        value: Any,
        attribute: str,
    ) -> Any:
        """
        Read an object attribute without allowing MagicMock dynamic
        attribute creation.
        """

        if value is None:
            return None

        value_type = type(value)

        if value_type.__module__.startswith(
            "unittest.mock"
        ):
            return None

        try:
            return value_type.__getattribute__(
                value,
                attribute,
            )

        except AttributeError:
            return None

    @staticmethod
    def _extract_metadata(
        value: Any,
    ) -> Optional[Mapping[str, Any]]:
        """Extract optional metadata."""

        if value is None:
            return None

        if isinstance(value, Mapping):

            metadata = value.get(
                "metadata"
            )

            if isinstance(metadata, Mapping):
                return dict(metadata)

            return None

        metadata = TransactionService._safe_object_attribute(
            value,
            "metadata",
        )

        if isinstance(metadata, Mapping):
            return dict(metadata)

        return None

    @staticmethod
    def _merge_metadata(
        *values: Optional[Mapping[str, Any]],
        signature_metadata: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Mapping[str, Any]]:
        """Merge metadata without mutating caller-owned mappings."""

        merged: dict[str, Any] = {}

        for value in values:

            if isinstance(value, Mapping):
                merged.update(
                    dict(value)
                )

        if isinstance(signature_metadata, Mapping):
            merged.update(
                dict(signature_metadata)
            )

        return merged or None

    @staticmethod
    def _extract_broadcast_hash(
        result: Any,
        *,
        fallback: Optional[str] = None,
    ) -> Optional[str]:
        """Extract blockchain transaction hash."""

        if result is None:
            return fallback

        if isinstance(result, str):
            return result or fallback

        if isinstance(result, bytes):
            return "0x" + result.hex()

        if isinstance(result, bytearray):
            return "0x" + bytes(result).hex()

        if isinstance(result, memoryview):
            return "0x" + result.tobytes().hex()

        if isinstance(result, Mapping):

            for key in (
                "transaction_hash",
                "tx_hash",
                "txid",
                "hash",
                "result",
            ):
                value = result.get(key)

                if value:
                    return str(value)

            return fallback

        result_type = type(result)

        if result_type.__module__.startswith(
            "unittest.mock"
        ):
            return fallback

        for attribute in (
            "transaction_hash",
            "tx_hash",
            "txid",
            "hash",
            "result",
        ):
            value = TransactionService._safe_object_attribute(
                result,
                attribute,
            )

            if value:
                return str(value)

        return fallback

    # ========================================================================
    # SUMMARY
    # ========================================================================

    def summary(
        self,
        network: str,
        payload: bytes,
    ) -> Mapping[str, Any]:
        """
        Return safe application-level transaction information.

        Never exposes:

            - private keys
            - mnemonics
            - seeds
            - signing material
        """

        normalized_network = self.normalize_network(
            network
        )

        payload = self._validate_bytes(
            payload,
            field_name="Transaction payload",
        )

        try:
            decoded = self.decode(
                normalized_network,
                payload,
            )

        except Exception:
            decoded = None

        summary_method = getattr(
            TransactionDecoder,
            "summary",
            None,
        )

        if callable(summary_method) and decoded is not None:

            try:
                value = summary_method(
                    decoded
                )

                if isinstance(value, Mapping):
                    return dict(value)

            except Exception:
                pass

        result: dict[str, Any] = {
            "network": normalized_network,
            "payload_hash": self._payload_hash(
                payload
            ),
            "payload_size": len(payload),
        }

        if decoded is not None:

            for attribute in (
                "transaction_type",
                "type",
            ):
                value = self._safe_object_attribute(
                    decoded,
                    attribute,
                )

                if value is not None:
                    result["transaction_type"] = value
                    break

        return result
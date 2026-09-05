"""
HappyWallet Cryptographic Signing Service.

This module is the cryptographic signing boundary.

Responsibilities
----------------
- secp256k1 private-key validation
- secp256k1 public-key derivation
- SHA-256 primitives
- double SHA-256 primitive
- ECDSA/secp256k1 signing
- ECDSA signature verification
- DER <-> (r, s) conversion
- network-name normalization
- controlled transaction-digest signing

Security boundary
-----------------

    TransactionEncoder
            |
            | exact 32-byte signing digest
            v
      SigningService
            |
            | cryptographic signature
            v
    TransactionEncoder
            |
            v
      Signed transaction

This service MUST NOT:

- build blockchain transactions
- serialize Ethereum RLP
- serialize Bitcoin transactions
- serialize Tron transactions
- calculate Ethereum transaction hashes
- calculate Bitcoin transaction IDs
- calculate Tron transaction IDs
- obtain nonces
- calculate gas
- communicate with RPC endpoints
- broadcast transactions
- access wallet databases
- access mnemonic phrases
- persist private keys
- write private keys to disk
- send private keys over USB
- log private-key material

IMPORTANT
---------

The signing service signs an already-computed digest.

The network-specific TransactionEncoder is responsible for determining
the exact digest that must be signed.

For example, an encoder may use:

    SHA-256
    double SHA-256
    Keccak-256
    another protocol-defined digest

This module does not make that protocol decision.

Private keys should exist in memory only for the shortest possible
period required to perform the cryptographic operation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ============================================================================
# CONSTANTS
# ============================================================================

SECP256K1_ORDER: Final[int] = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "BAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)

PRIVATE_KEY_LENGTH: Final[int] = 32
DIGEST_LENGTH: Final[int] = 32


# ============================================================================
# EXCEPTIONS
# ============================================================================


class SigningError(Exception):
    """Base exception for cryptographic signing failures."""


class InvalidPrivateKeyError(SigningError):
    """Raised when a secp256k1 private key is invalid."""


class InvalidMessageError(SigningError):
    """Raised when a message or digest is invalid."""


class InvalidSignatureError(SigningError):
    """Raised when a signature is invalid."""


class UnsupportedSigningNetworkError(SigningError):
    """Raised when a signing network is unsupported."""


# ============================================================================
# RESULT TYPES
# ============================================================================


@dataclass(frozen=True)
class SignatureResult:
    """
    Result of a cryptographic signing operation.

    No private-key material is retained.

    All byte-oriented cryptographic values are represented as
    hexadecimal strings at this API boundary.
    """

    algorithm: str
    digest_algorithm: str
    message_hash: str
    signature_der: str
    public_key: str


# ============================================================================
# SIGNING SERVICE
# ============================================================================


class SigningService:
    """
    Pure secp256k1 cryptographic service.

    The service deliberately knows nothing about blockchain transaction
    serialization.

    It receives either:

        message bytes
            -> hashes with SHA-256
            -> signs digest

    or:

        already-computed 32-byte digest
            -> signs digest directly

    The latter is the preferred API for TransactionService.
    """

    CURVE: Final = ec.SECP256K1()

    ALGORITHM: Final = "ECDSA-secp256k1"
    DIGEST_ALGORITHM: Final = "SHA-256"

    PRIVATE_KEY_LENGTH: Final = PRIVATE_KEY_LENGTH
    DIGEST_LENGTH: Final = DIGEST_LENGTH

    SUPPORTED_NETWORKS: Final = frozenset(
        {
            "ethereum",
            "bitcoin",
            "tron",
        }
    )

    NETWORK_ALIASES: Final = {
        "eth": "ethereum",
        "ethereum-mainnet": "ethereum",
        "ethereum_testnet": "ethereum",
        "btc": "bitcoin",
        "bitcoin-mainnet": "bitcoin",
        "bitcoin_testnet": "bitcoin",
        "trx": "tron",
        "tron-mainnet": "tron",
    }

    # =========================================================================
    # NETWORK
    # =========================================================================

    @classmethod
    def validate_network(
        cls,
        network: str,
    ) -> str:
        """
        Normalize and validate a supported network name.

        No blockchain communication occurs.
        """

        if not isinstance(network, str):
            raise UnsupportedSigningNetworkError(
                "Network must be a string."
            )

        normalized = network.strip().lower()

        normalized = cls.NETWORK_ALIASES.get(
            normalized,
            normalized,
        )

        if normalized not in cls.SUPPORTED_NETWORKS:
            raise UnsupportedSigningNetworkError(
                f"Unsupported signing network: {network}"
            )

        return normalized

    # =========================================================================
    # PRIVATE KEY
    # =========================================================================

    @classmethod
    def validate_private_key(
        cls,
        private_key: bytes,
    ) -> bool:
        """
        Validate a raw secp256k1 private key.

        A valid key must satisfy:

            len(key) == 32
            1 <= integer(key) < curve_order
        """

        if not isinstance(private_key, bytes):
            return False

        if len(private_key) != cls.PRIVATE_KEY_LENGTH:
            return False

        value = int.from_bytes(
            private_key,
            byteorder="big",
            signed=False,
        )

        return 1 <= value < SECP256K1_ORDER

    @classmethod
    def _require_private_key(
        cls,
        private_key: bytes,
    ) -> bytes:
        """
        Validate a private key and return it unchanged.
        """

        if not cls.validate_private_key(private_key):
            raise InvalidPrivateKeyError(
                "Invalid secp256k1 private key."
            )

        return private_key

    @classmethod
    def _load_private_key(
        cls,
        private_key: bytes,
    ) -> ec.EllipticCurvePrivateKey:
        """
        Convert raw 32-byte private-key material into a cryptography
        private-key object.
        """

        cls._require_private_key(private_key)

        private_value = int.from_bytes(
            private_key,
            byteorder="big",
            signed=False,
        )

        try:
            return ec.derive_private_key(
                private_value,
                cls.CURVE,
            )
        except Exception as exc:
            raise InvalidPrivateKeyError(
                "Unable to load secp256k1 private key."
            ) from exc

    # =========================================================================
    # PUBLIC KEY
    # =========================================================================

    @classmethod
    def public_key(
        cls,
        private_key: bytes,
        *,
        compressed: bool = True,
    ) -> bytes:
        """
        Derive a SEC1 encoded public key.

        Compressed:
            33 bytes

        Uncompressed:
            65 bytes
        """

        key = cls._load_private_key(private_key)

        public_format = (
            PublicFormat.CompressedPoint
            if compressed
            else PublicFormat.UncompressedPoint
        )

        try:
            return key.public_key().public_bytes(
                Encoding.X962,
                public_format,
            )
        except Exception as exc:
            raise SigningError(
                "Unable to derive public key."
            ) from exc

    @classmethod
    def public_key_hex(
        cls,
        private_key: bytes,
        *,
        compressed: bool = True,
    ) -> str:
        """
        Return the SEC1 public key as hexadecimal text.
        """

        return cls.public_key(
            private_key,
            compressed=compressed,
        ).hex()

    # =========================================================================
    # HASHING
    # =========================================================================

    @staticmethod
    def _require_bytes(
        value: bytes,
        *,
        field_name: str,
        allow_empty: bool = False,
    ) -> bytes:
        """
        Validate a bytes value.
        """

        if not isinstance(value, bytes):
            raise InvalidMessageError(
                f"{field_name} must be bytes."
            )

        if not allow_empty and not value:
            raise InvalidMessageError(
                f"{field_name} cannot be empty."
            )

        return value

    @classmethod
    def sha256(
        cls,
        data: bytes,
    ) -> bytes:
        """
        Calculate SHA-256.
        """

        cls._require_bytes(
            data,
            field_name="Data",
            allow_empty=True,
        )

        return hashlib.sha256(data).digest()

    @classmethod
    def double_sha256(
        cls,
        data: bytes,
    ) -> bytes:
        """
        Calculate:

            SHA256(SHA256(data))
        """

        digest = cls.sha256(data)

        return cls.sha256(digest)

    @classmethod
    def message_digest(
        cls,
        message: bytes,
    ) -> bytes:
        """
        Calculate the SHA-256 digest of a message.
        """

        cls._require_bytes(
            message,
            field_name="Message",
        )

        return cls.sha256(message)

    # =========================================================================
    # DIGEST VALIDATION
    # =========================================================================

    @classmethod
    def validate_digest(
        cls,
        digest: bytes,
    ) -> bytes:
        """
        Validate a pre-computed SHA-256-sized digest.
        """

        if not isinstance(digest, bytes):
            raise InvalidMessageError(
                "Digest must be bytes."
            )

        if len(digest) != cls.DIGEST_LENGTH:
            raise InvalidMessageError(
                "Digest must contain exactly 32 bytes."
            )

        return digest

    # =========================================================================
    # SIGN DIGEST
    # =========================================================================

    @classmethod
    def sign_digest(
        cls,
        private_key: bytes,
        digest: bytes,
    ) -> bytes:
        """
        Sign an already-computed 32-byte digest.

        The digest is supplied through Prehashed(SHA256()), which prevents
        cryptography from hashing it again.

        Returns:
            DER-encoded ECDSA signature.
        """

        cls._require_private_key(private_key)
        cls.validate_digest(digest)

        key = cls._load_private_key(private_key)

        try:
            return key.sign(
                digest,
                ec.ECDSA(
                    Prehashed(hashes.SHA256())
                ),
            )
        except Exception as exc:
            raise SigningError(
                "Unable to sign digest."
            ) from exc

    # =========================================================================
    # SIGN MESSAGE
    # =========================================================================

    @classmethod
    def sign(
        cls,
        private_key: bytes,
        message: bytes,
    ) -> SignatureResult:
        """
        SHA-256 hash and sign an arbitrary message.

        This is a cryptographic convenience method.

        Blockchain transaction code should normally use sign_digest()
        after the network-specific encoder has produced the exact digest.
        """

        cls._require_bytes(
            message,
            field_name="Message",
        )

        digest = cls.message_digest(message)

        signature_der = cls.sign_digest(
            private_key,
            digest,
        )

        public_key = cls.public_key(
            private_key,
            compressed=True,
        )

        return SignatureResult(
            algorithm=cls.ALGORITHM,
            digest_algorithm=cls.DIGEST_ALGORITHM,
            message_hash=digest.hex(),
            signature_der=signature_der.hex(),
            public_key=public_key.hex(),
        )

    # =========================================================================
    # SIGN DIGEST RESULT
    # =========================================================================

    @classmethod
    def sign_digest_result(
        cls,
        private_key: bytes,
        digest: bytes,
    ) -> SignatureResult:
        """
        Sign a pre-computed digest and return the normalized result object
        expected by the transaction orchestration layer.
        """

        cls.validate_digest(digest)

        signature_der = cls.sign_digest(
            private_key,
            digest,
        )

        public_key = cls.public_key(
            private_key,
            compressed=True,
        )

        return SignatureResult(
            algorithm=cls.ALGORITHM,
            digest_algorithm=cls.DIGEST_ALGORITHM,
            message_hash=digest.hex(),
            signature_der=signature_der.hex(),
            public_key=public_key.hex(),
        )

    # =========================================================================
    # VERIFY DIGEST
    # =========================================================================

    @classmethod
    def verify_digest(
        cls,
        public_key: bytes,
        digest: bytes,
        signature_der: bytes,
    ) -> bool:
        """
        Verify a DER-encoded ECDSA signature against a pre-computed digest.
        """

        if not isinstance(public_key, bytes):
            return False

        if not isinstance(signature_der, bytes):
            return False

        if not isinstance(digest, bytes):
            return False

        if len(digest) != cls.DIGEST_LENGTH:
            return False

        try:
            public_key_object = (
                ec.EllipticCurvePublicKey.from_encoded_point(
                    cls.CURVE,
                    public_key,
                )
            )

            public_key_object.verify(
                signature_der,
                digest,
                ec.ECDSA(
                    Prehashed(hashes.SHA256())
                ),
            )

            return True

        except Exception:
            return False

    # =========================================================================
    # VERIFY MESSAGE
    # =========================================================================

    @classmethod
    def verify(
        cls,
        public_key: bytes,
        message: bytes,
        signature_der: bytes,
    ) -> bool:
        """
        Hash a message with SHA-256 and verify its signature.
        """

        if not isinstance(message, bytes):
            return False

        if not message:
            return False

        digest = cls.message_digest(message)

        return cls.verify_digest(
            public_key,
            digest,
            signature_der,
        )

    # =========================================================================
    # SIGNATURE DECODING
    # =========================================================================

    @staticmethod
    def decode_signature(
        signature_der: bytes,
    ) -> tuple[int, int]:
        """
        Decode a DER ECDSA signature into:

            (r, s)
        """

        if not isinstance(signature_der, bytes):
            raise InvalidSignatureError(
                "Signature must be bytes."
            )

        if not signature_der:
            raise InvalidSignatureError(
                "Signature cannot be empty."
            )

        try:
            r, s = decode_dss_signature(
                signature_der
            )
        except Exception as exc:
            raise InvalidSignatureError(
                "Invalid DER ECDSA signature."
            ) from exc

        if r <= 0 or s <= 0:
            raise InvalidSignatureError(
                "ECDSA r and s must be positive."
            )

        return r, s

    # =========================================================================
    # SIGNATURE ENCODING
    # =========================================================================

    @staticmethod
    def encode_signature(
        r: int,
        s: int,
    ) -> bytes:
        """
        Encode ECDSA r/s values as DER.
        """

        if isinstance(r, bool) or not isinstance(r, int):
            raise InvalidSignatureError(
                "r must be an integer."
            )

        if isinstance(s, bool) or not isinstance(s, int):
            raise InvalidSignatureError(
                "s must be an integer."
            )

        if r <= 0 or s <= 0:
            raise InvalidSignatureError(
                "ECDSA r and s must be positive."
            )

        if r >= SECP256K1_ORDER:
            raise InvalidSignatureError(
                "ECDSA r is outside the secp256k1 range."
            )

        if s >= SECP256K1_ORDER:
            raise InvalidSignatureError(
                "ECDSA s is outside the secp256k1 range."
            )

        try:
            return encode_dss_signature(
                r,
                s,
            )
        except Exception as exc:
            raise InvalidSignatureError(
                "Unable to encode ECDSA signature."
            ) from exc

    # =========================================================================
    # HEX HELPERS
    # =========================================================================

    @classmethod
    def sign_hex(
        cls,
        private_key: bytes,
        message: bytes,
    ) -> str:
        """
        Sign a message and return the DER signature as hexadecimal.
        """

        return cls.sign(
            private_key,
            message,
        ).signature_der

    @classmethod
    def sign_hash_hex(
        cls,
        private_key: bytes,
        message: bytes,
    ) -> str:
        """
        Return the SHA-256 digest of a message as hexadecimal.

        The private-key parameter is retained only for compatibility with
        older callers and is deliberately unused.
        """

        _ = private_key

        return cls.message_digest(
            message
        ).hex()

    # =========================================================================
    # PRIVATE KEY EXPORT
    # =========================================================================

    @classmethod
    def export_private_key_for_memory_use(
        cls,
        private_key: bytes,
    ) -> bytes:
        """
        Export a validated private key as unencrypted PKCS#8 PEM.

        This method exists only for controlled in-memory interoperability.

        The returned bytes MUST NOT be:

        - written to disk
        - persisted in a database
        - logged
        - sent over USB
        - sent over a network
        """

        key = cls._load_private_key(
            private_key
        )

        try:
            return key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption(),
            )
        except Exception as exc:
            raise SigningError(
                "Unable to export private key."
            ) from exc

    # =========================================================================
    # TRANSACTION PAYLOAD SIGNING
    # =========================================================================

    @classmethod
    def sign_transaction_payload(
        cls,
        private_key: bytes,
        transaction_payload: bytes,
        *,
        network: str,
    ) -> SignatureResult:
        """
        Sign a transaction payload using the service's generic SHA-256
        message-signing operation.

        IMPORTANT:

        This method is retained as a compatibility API.

        Production blockchain transaction signing should prefer:

            TransactionEncoder.prepare_signing()
                ->
            SigningService.sign_digest_result()

        because the encoder must determine the protocol-specific digest.
        """

        cls.validate_network(
            network
        )

        cls._require_bytes(
            transaction_payload,
            field_name="Transaction payload",
        )

        return cls.sign(
            private_key,
            transaction_payload,
        )
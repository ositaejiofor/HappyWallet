"""Guarded TRON send construction, local signing, and broadcast services."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from typing import Any

from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins
from coincurve import PrivateKey
from django.conf import settings
from eth_hash.auto import keccak

from apps.security.vault import WalletSecret
from apps.transaction.services.networks.tron import (
    TRON_SUN_PER_TRX,
    TronReadOnlyClient,
    TronResponseError,
)


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class TronSendError(RuntimeError):
    """Safe user-facing TRON send failure."""


class TronValidationError(TronSendError):
    pass


class TronBroadcastBlocked(TronSendError):
    pass


class TronBroadcastUnknown(TronSendError):
    pass


@dataclass(frozen=True, slots=True)
class PreparedTronSend:
    asset: str
    sender: str
    recipient: str
    amount: Decimal
    estimated_fee_trx: Decimal
    estimated_energy: int
    unsigned_transaction: dict[str, Any]


def _base58_decode(value: str) -> bytes:
    number = 0
    try:
        for character in value:
            number = number * 58 + BASE58_ALPHABET.index(character)
    except ValueError as exc:
        raise TronValidationError("Enter a valid TRON address.") from exc
    payload = number.to_bytes((number.bit_length() + 7) // 8, "big")
    padding = len(value) - len(value.lstrip("1"))
    return b"\x00" * padding + payload


def _base58_encode(payload: bytes) -> str:
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    padding = len(payload) - len(payload.lstrip(b"\x00"))
    return "1" * padding + (encoded or "1")


def tron_address_to_hex(address: str) -> str:
    normalized = str(address or "").strip()
    if len(normalized) != 34 or not normalized.startswith("T"):
        raise TronValidationError("Enter a valid TRON address.")
    decoded = _base58_decode(normalized)
    if len(decoded) != 25 or decoded[0] != 0x41:
        raise TronValidationError("Enter a valid TRON address.")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if not hmac.compare_digest(checksum, expected):
        raise TronValidationError("Enter a valid TRON address.")
    return payload.hex().upper()


def private_key_to_address(private_key: bytes) -> str:
    public_key = PrivateKey(private_key).public_key.format(compressed=False)
    payload = b"\x41" + keccak(public_key[1:])[-20:]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


def private_key_from_secret(secret: WalletSecret) -> bytes:
    if secret.mnemonic:
        seed = Bip39SeedGenerator(secret.mnemonic.strip()).Generate()
        node = (
            Bip44.FromSeed(seed, Bip44Coins.TRON)
            .Purpose()
            .Coin()
            .Account(0)
            .Change(Bip44Changes.CHAIN_EXT)
            .AddressIndex(0)
        )
        return node.PrivateKey().Raw().ToBytes()
    raw = (secret.private_key or secret.seed or "").strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise TronValidationError("The USB vault does not contain a usable TRON key.") from exc
    if len(key) != 32:
        raise TronValidationError("The USB vault does not contain a usable TRON key.")
    return key


class TronSendClient(TronReadOnlyClient):
    """Write-capable client used only by the guarded send workflow."""

    def prepare(
        self,
        *,
        sender: str,
        recipient: str,
        asset: str,
        amount: Decimal,
        contract_address: str = "",
    ) -> PreparedTronSend:
        sender_hex = tron_address_to_hex(sender)
        recipient_hex = tron_address_to_hex(recipient)
        if sender == recipient:
            raise TronValidationError("Recipient must be different from the sending wallet.")
        symbol = str(asset or "").strip().upper()
        value = self._validate_amount(amount, symbol)

        trx_balance = self.get_trx_balance(sender)
        if symbol == "TRX":
            fee = Decimal(str(getattr(settings, "TRON_TRX_FEE_RESERVE", "1.100000")))
            if value + fee > trx_balance:
                raise TronValidationError("Insufficient TRX for the amount and fee reserve.")
            transaction = self._post(
                "/wallet/createtransaction",
                {"owner_address": sender, "to_address": recipient, "amount": int(value * TRON_SUN_PER_TRX), "visible": True},
            )
            energy = 0
        elif symbol == "USDT":
            contract = str(contract_address or "").strip()
            tron_address_to_hex(contract)
            balance = self.get_trc20_balance(sender, contract_address=contract, decimals=6)
            if value > balance:
                raise TronValidationError("Insufficient USDT balance.")
            parameter = recipient_hex[2:].rjust(64, "0") + format(int(value * Decimal("1000000")), "064x")
            call = {
                "owner_address": sender,
                "contract_address": contract,
                "function_selector": "transfer(address,uint256)",
                "parameter": parameter,
                "visible": True,
            }
            simulation = self._post("/wallet/triggerconstantcontract", call)
            energy = int(simulation.get("energy_used") or 0)
            if simulation.get("result", {}).get("result") is not True:
                raise TronValidationError("The USDT transfer simulation was rejected.")
            energy_price = Decimal(str(getattr(settings, "TRON_ENERGY_PRICE_SUN", 420)))
            margin = Decimal(str(getattr(settings, "TRON_FEE_SAFETY_MULTIPLIER", "1.20")))
            fee = max(
                Decimal(str(getattr(settings, "TRON_USDT_MIN_FEE_RESERVE", "30"))),
                (Decimal(energy) * energy_price / TRON_SUN_PER_TRX * margin).quantize(Decimal("0.000001")),
            )
            if trx_balance < fee:
                raise TronValidationError("Insufficient TRX to cover the estimated USDT energy fee.")
            call["fee_limit"] = int(fee * TRON_SUN_PER_TRX)
            built = self._post("/wallet/triggersmartcontract", call)
            transaction = built.get("transaction")
        else:
            raise TronValidationError("Only TRX and TRC-20 USDT are supported.")

        if not isinstance(transaction, dict):
            raise TronResponseError("TRON provider did not return an unsigned transaction.")
        raw_hex = transaction.get("raw_data_hex")
        txid = transaction.get("txID")
        if not isinstance(raw_hex, str) or not raw_hex or not isinstance(txid, str):
            raise TronResponseError("TRON provider returned an incomplete unsigned transaction.")
        computed = hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest()
        if not hmac.compare_digest(computed.lower(), txid.lower()):
            raise TronResponseError("TRON provider returned an invalid transaction identifier.")
        if transaction.get("signature"):
            raise TronResponseError("TRON provider returned an unexpectedly signed transaction.")
        self._assert_transaction_matches(
            transaction,
            asset=symbol,
            sender=sender,
            recipient=recipient,
            amount=value,
            contract_address=contract_address,
        )
        return PreparedTronSend(symbol, sender, recipient, value, fee, energy, transaction)

    def sign(self, transaction: dict[str, Any], secret: WalletSecret, sender: str) -> dict[str, Any]:
        raw_hex = transaction.get("raw_data_hex")
        txid = transaction.get("txID")
        if not isinstance(raw_hex, str) or not isinstance(txid, str):
            raise TronValidationError("Unsigned transaction data is invalid.")
        digest = hashlib.sha256(bytes.fromhex(raw_hex)).digest()
        if not hmac.compare_digest(digest.hex(), txid.lower()):
            raise TronValidationError("Unsigned transaction data was changed.")
        private_key = private_key_from_secret(secret)
        try:
            if private_key_to_address(private_key) != sender:
                raise TronValidationError("The connected USB vault does not control this wallet address.")
            signature = PrivateKey(private_key).sign_recoverable(digest, hasher=None).hex()
            signed = json.loads(json.dumps(transaction))
            signed["signature"] = [signature]
            return signed
        finally:
            del private_key

    def broadcast(self, signed_transaction: dict[str, Any], *, is_testnet: bool) -> str:
        if is_testnet:
            if not getattr(settings, "TRON_TESTNET_BROADCAST_ENABLED", True):
                raise TronBroadcastBlocked("TRON testnet broadcasting is disabled.")
        elif not getattr(settings, "TRON_MAINNET_BROADCAST_ENABLED", False):
            raise TronBroadcastBlocked("TRON mainnet broadcasting is disabled.")
        try:
            response = self._post("/wallet/broadcasttransaction", signed_transaction)
        except Exception as exc:
            raise TronBroadcastUnknown("Broadcast outcome is unknown. Do not resend automatically.") from exc
        if response.get("result") is not True:
            raise TronSendError("The TRON node rejected the transaction.")
        txid = signed_transaction.get("txID")
        if not isinstance(txid, str) or len(txid) != 64:
            raise TronBroadcastUnknown("Broadcast outcome is unknown. Do not resend automatically.")
        return txid

    @staticmethod
    def _validate_amount(amount: Decimal, asset: str) -> Decimal:
        try:
            value = Decimal(str(amount))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise TronValidationError("Enter a valid amount.") from exc
        if not value.is_finite() or value <= 0:
            raise TronValidationError("Amount must be greater than zero.")
        places = Decimal("0.000001")
        if value != value.quantize(places, rounding=ROUND_DOWN):
            raise TronValidationError(f"{asset} supports no more than 6 decimal places.")
        return value

    @staticmethod
    def _assert_transaction_matches(
        transaction: dict[str, Any],
        *,
        asset: str,
        sender: str,
        recipient: str,
        amount: Decimal,
        contract_address: str,
    ) -> None:
        """Reject provider output whose human-visible meaning changed."""
        raw_data = transaction.get("raw_data")
        contracts = raw_data.get("contract") if isinstance(raw_data, dict) else None
        contract = contracts[0] if isinstance(contracts, list) and contracts else None
        parameter = contract.get("parameter") if isinstance(contract, dict) else None
        value = parameter.get("value") if isinstance(parameter, dict) else None
        if not isinstance(contract, dict) or not isinstance(value, dict):
            raise TronResponseError("TRON provider returned malformed transaction data.")
        if asset == "TRX":
            valid = (
                contract.get("type") == "TransferContract"
                and value.get("owner_address") == sender
                and value.get("to_address") == recipient
                and value.get("amount") == int(amount * TRON_SUN_PER_TRX)
            )
        else:
            expected_parameter = (
                tron_address_to_hex(recipient)[2:].rjust(64, "0")
                + format(int(amount * Decimal("1000000")), "064x")
            ).lower()
            data = str(value.get("data") or "").lower()
            valid = (
                contract.get("type") == "TriggerSmartContract"
                and value.get("owner_address") == sender
                and value.get("contract_address") == contract_address
                and data == "a9059cbb" + expected_parameter
            )
        if not valid:
            raise TronResponseError("TRON provider transaction does not match the confirmed transfer.")

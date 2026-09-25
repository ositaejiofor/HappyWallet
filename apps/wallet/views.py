"""
HappyWallet wallet views.

Views are HTTP/controller boundaries.

Security boundary
-----------------

This module:

- handles authentication and HTTP requests
- validates form input
- delegates wallet operations to application services
- never generates mnemonics
- never derives private keys
- never persists plaintext wallet secrets
- never places wallet secrets in sessions
- never places wallet secrets in templates
- never places wallet secrets in messages

Sensitive wallet material is handled by the wallet/security service layer.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID
import hashlib
import secrets
from datetime import datetime, timedelta

import qrcode
from qrcode.image.svg import SvgPathFillImage

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_http_methods
from django.shortcuts import redirect, render
from django.db import transaction, IntegrityError
from django.utils import timezone

from apps.blockchain.models import BlockchainNetwork
from apps.security.vault import InvalidPasswordError
from apps.transaction.services.history import get_wallet_transaction_history
from apps.transaction.models import TronSendIntent
from apps.transaction.services.tron_send import (
    TronBroadcastBlocked,
    TronBroadcastUnknown,
    TronSendClient,
    TronSendError,
)
from apps.usb_manager.detector import USBDetector
from apps.usb_manager.vault import USBVault, USBVaultError
from apps.wallet.models import Wallet
from apps.wallet.services.address import WalletAddressService
from apps.wallet.services.creation import (
    WalletCreationError,
    WalletCreationService,
)
from apps.wallet.services.vault import WalletVaultService
from apps.wallet.services.wallet_balance import (
    WalletDashboardBalanceService,
)

from .forms import (
    CreateWalletForm,
    TronSendConfirmForm,
    TronSendPrepareForm,
    UnlockWalletForm,
)
from .services.wallet import WalletService


APP_NAME = "HappyWallet"
DEFAULT_NETWORK_SLUG = "ethereum-mainnet"
TRON_NETWORK_IDENTIFIERS = frozenset(
    {"tron", "tron-mainnet", "tron-main-net", "trx", "trx-mainnet", "tron-shasta-testnet", "tron-testnet"}
)


# ============================================================================
# WALLET HELPERS
# ============================================================================


def _get_user_wallets(user):
    """Return the authenticated user's public wallet records."""

    if user is None:
        return Wallet.objects.none()

    return (
        Wallet.objects
        .select_related("network")
        .filter(user=user)
        .order_by("-created_at", "-id")
    )


def _get_user_wallet(
    user,
    wallet_id: str | None = None,
) -> Wallet | None:
    """
    Return the user's wallet with its network loaded.

    This helper performs no wallet-secret operations.
    """

    wallets = _get_user_wallets(user)

    if not wallet_id:
        return wallets.first()

    try:
        selected_id = UUID(str(wallet_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise Http404("Wallet not found.") from exc

    wallet = wallets.filter(pk=selected_id).first()

    if wallet is None:
        # The same response is used for unknown and foreign wallet IDs.
        raise Http404("Wallet not found.")

    return wallet


def _get_wallet_address(wallet: Wallet) -> str:
    """
    Return the wallet's public address.

    Only public address data is returned.
    """

    if wallet is None:
        return ""

    address = WalletAddressService().get_address(
        wallet=wallet,
    )

    if address:
        return address.address

    return (wallet.address or "").strip()


def _is_tron_wallet(wallet: Wallet) -> bool:
    """Return whether the wallet belongs to a supported TRON network."""

    network = getattr(wallet, "network", None)
    candidates = (
        getattr(network, "slug", ""),
        getattr(network, "name", ""),
        getattr(network, "symbol", ""),
    )
    return any(
        str(candidate).strip().lower().replace("_", "-").replace(" ", "-")
        in TRON_NETWORK_IDENTIFIERS
        for candidate in candidates
    )


def _get_receive_wallet(*, user, wallet_id: UUID) -> Wallet:
    """Resolve one active, owned TRON wallet without exposing foreign IDs."""

    wallet = (
        Wallet.objects
        .select_related("network")
        .filter(pk=wallet_id, user=user, status=Wallet.Status.ACTIVE)
        .first()
    )
    if wallet is None or not _is_tron_wallet(wallet):
        raise Http404("Wallet not found.")
    return wallet


def _validate_tron_receive_address(address: str) -> str:
    """Validate the public Base58 address used by the receive-only flow."""

    normalized = str(address or "").strip()
    base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if (
        len(normalized) != 34
        or not normalized.startswith("T")
        or any(character not in base58 for character in normalized)
    ):
        raise Http404("Wallet address is unavailable.")
    return normalized


def _build_assets(balance) -> list[dict]:
    """
    Build dashboard asset data from the public balance service result.

    No private wallet material is accessed here.
    """

    assets: list[dict] = []

    if balance.native_symbol:
        assets.append(
            {
                "name": (
                    "Ethereum"
                    if balance.native_symbol.upper() == "ETH"
                    else balance.native_symbol
                ),
                "symbol": balance.native_symbol,
                "network": balance.network,
                "balance": balance.native_balance,
                "value": Decimal("0"),
                "is_native": True,
            }
        )

    for token in balance.tokens:
        assets.append(
            {
                "name": token.name,
                "symbol": token.symbol,
                "network": balance.network,
                "balance": token.balance,
                "value": Decimal("0"),
                "is_native": False,
                "address": token.address,
            }
        )

    return assets


def _wallet_status_context(wallet: Wallet) -> dict[str, object]:
    """
    Build the wallet lifecycle status context used by dashboard templates.

    This exposes only boolean lifecycle state and the human-readable
    status label. No wallet secrets are accessed or exposed.
    """

    return {
        "wallet_status": wallet.get_status_display(),
        "wallet_unlocked": wallet.status == Wallet.Status.ACTIVE,
        "wallet_locked": wallet.status == Wallet.Status.LOCKED,
    }


def _locked_wallet_context(wallet: Wallet) -> dict[str, object]:
    """
    Build the minimal dashboard context for a locked wallet.

    IMPORTANT
    ---------

    This context intentionally contains:

    - no wallet address
    - no balance
    - no assets
    - no blockchain data
    - no network details

    This prevents the locked dashboard from loading or rendering
    wallet information that is unnecessary while the wallet is locked.
    """

    return {
        "app_name": APP_NAME,
        "wallet": wallet,
        "wallet_address": "",
        "has_address": False,
        "network": "",
        "network_symbol": "",
        "blockchain_available": False,
        "native_symbol": "",
        "native_balance": Decimal("0"),
        "balance": Decimal("0"),
        "currency": "ETH",
        "assets": [],
        "asset_count": 0,
        **_wallet_status_context(wallet),
    }


# ============================================================================
# WALLET DASHBOARD
# ============================================================================


@login_required
def wallet_home(request):
    """
    Display the user's wallet dashboard.

    Security behavior
    -----------------

    LOCKED wallet:
        Only lifecycle state is exposed to the template.
        No balance, address, assets, or blockchain information
        is loaded.

    ACTIVE wallet:
        Public dashboard information such as address, balance,
        network, and assets may be loaded.

    No private wallet material is exposed by this view.
    """

    wallets = tuple(_get_user_wallets(request.user))
    wallet = _get_user_wallet(
        request.user,
        request.GET.get("wallet"),
    )
    selection_context = {
        "wallet_options": wallets,
        "selected_wallet_id": str(wallet.pk) if wallet else "",
    }

    # ------------------------------------------------------------------------
    # NO WALLET
    # ------------------------------------------------------------------------

    if wallet is None:
        return render(
            request,
            "wallet/home.html",
            {
                "app_name": APP_NAME,
                "wallet": None,
                "wallet_address": "",
                "has_address": False,
                "wallet_status": "Locked",
                "wallet_unlocked": False,
                "wallet_locked": True,
                "network": "Not configured",
                "network_symbol": "",
                "blockchain_available": False,
                "native_symbol": "",
                "native_balance": Decimal("0"),
                "balance": Decimal("0"),
                "currency": "ETH",
                "assets": [],
                "asset_count": 0,
                **selection_context,
            },
        )

    # ------------------------------------------------------------------------
    # LOCKED WALLET
    # ------------------------------------------------------------------------
    #
    # IMPORTANT:
    #
    # This check MUST happen before:
    #
    #   WalletDashboardBalanceService().get()
    #   _build_assets()
    #   _get_wallet_address()
    #
    # Therefore a locked wallet does not perform unnecessary public
    # blockchain/balance/address work.
    #
    # The template receives only the lifecycle state needed to display
    # the locked-wallet screen.
    # ------------------------------------------------------------------------

    if wallet.status != Wallet.Status.ACTIVE:
        return render(
            request,
            "wallet/home.html",
            {
                **_locked_wallet_context(wallet),
                **selection_context,
            },
        )

    # ------------------------------------------------------------------------
    # ACTIVE / UNLOCKED WALLET
    # ------------------------------------------------------------------------

    balance = WalletDashboardBalanceService().get(
        wallet=wallet,
    )

    assets = _build_assets(balance)
    native_symbol = balance.native_symbol or "ETH"
    address = _get_wallet_address(wallet)

    context = {
        "app_name": APP_NAME,
        "wallet": wallet,
        "wallet_address": address,
        "has_address": bool(address),
        "network": balance.network,
        "network_symbol": balance.network_symbol,
        "blockchain_available": balance.blockchain_available,
        "native_symbol": native_symbol,
        "native_balance": balance.native_balance,
        "balance": balance.native_balance,
        "currency": native_symbol,
        "assets": assets,
        "asset_count": len(assets),
        "wallet_is_tron": native_symbol.upper() == "TRX",
        "tron_usdt_contract_address": getattr(
            settings,
            "TRON_USDT_CONTRACT_ADDRESS",
            "",
        ),
        **selection_context,
        **_wallet_status_context(wallet),
    }

    return render(
        request,
        "wallet/home.html",
        context,
    )


# ============================================================================
# READ-ONLY TRON RECEIVE FLOW
# ============================================================================


@login_required
@require_GET
def tron_receive_qr(request, wallet_id: UUID) -> HttpResponse:
    """Return a locally generated SVG QR code for an owned TRON address."""

    wallet = _get_receive_wallet(user=request.user, wallet_id=wallet_id)
    address = _validate_tron_receive_address(_get_wallet_address(wallet))
    image = qrcode.make(address, image_factory=SvgPathFillImage)
    response = HttpResponse(
        image.to_string(encoding="unicode"),
        content_type="image/svg+xml; charset=utf-8",
    )
    response["Cache-Control"] = "no-store, private"
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'"
    )
    response["Referrer-Policy"] = "no-referrer"
    return response


@login_required
@require_GET
def tron_usdt_receive_status(request, wallet_id: UUID) -> JsonResponse:
    """Return confirmed incoming USDT activity for an owned TRON wallet."""

    wallet = _get_receive_wallet(user=request.user, wallet_id=wallet_id)
    _validate_tron_receive_address(_get_wallet_address(wallet))
    history = get_wallet_transaction_history(wallet=wallet)

    incoming = tuple(
        transaction
        for transaction in history.transactions
        if (
            str(transaction.symbol or "").upper() == "USDT"
            and transaction.transaction_type == "receive"
            and transaction.status == "confirmed"
        )
    )
    latest = incoming[0] if incoming else None
    payload = {
        "available": bool(history.available),
        "confirmed_deposit_count": len(incoming),
        "latest": None,
        "contract_address": getattr(
            settings,
            "TRON_USDT_CONTRACT_ADDRESS",
            "",
        ),
        "network": "TRON Mainnet",
        "read_only": True,
    }
    if latest is not None:
        payload["latest"] = {
            "transaction_hash": latest.transaction_hash,
            "amount": (
                format(latest.amount, "f")
                if latest.amount is not None
                else None
            ),
            "symbol": latest.symbol,
            "timestamp": latest.timestamp,
        }

    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store, private"
    response["X-Content-Type-Options"] = "nosniff"
    return response


# ============================================================================
# GUARDED TRON SEND FLOW
# ============================================================================


def _tron_rpc_url_for(wallet: Wallet) -> str:
    if wallet.network and wallet.network.is_testnet:
        return getattr(settings, "TRON_TESTNET_RPC_URL", "https://api.shasta.trongrid.io")
    return getattr(settings, "TRON_RPC_URL", "https://api.trongrid.io")


def _available_usb_vaults() -> list[dict[str, str]]:
    result = []
    for device in USBDetector().detect():
        vault = USBVault(device)
        try:
            if not vault.exists():
                continue
            metadata = vault.read_metadata()
        except (USBVaultError, OSError, ValueError):
            continue
        result.append({
            "device_id": device.device_id,
            "label": device.label or "HappyWallet USB vault",
            "vault_id": metadata.vault_id,
        })
    return result


@login_required
@require_http_methods(["GET", "POST"])
def tron_send_prepare(request, wallet_id: UUID):
    wallet = _get_receive_wallet(user=request.user, wallet_id=wallet_id)
    sender = _validate_tron_receive_address(_get_wallet_address(wallet))
    form = TronSendPrepareForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        client = TronSendClient(rpc_url=_tron_rpc_url_for(wallet))
        try:
            prepared = client.prepare(
                sender=sender,
                recipient=form.cleaned_data["recipient"],
                asset=form.cleaned_data["asset"],
                amount=form.cleaned_data["amount"],
                contract_address=(
                    getattr(settings, "TRON_TESTNET_USDT_CONTRACT_ADDRESS", "")
                    if wallet.network.is_testnet
                    else getattr(settings, "TRON_USDT_CONTRACT_ADDRESS", "")
                ),
            )
            raw_expiration = prepared.unsigned_transaction.get("raw_data", {}).get("expiration")
            try:
                provider_expiry = datetime.fromtimestamp(
                    int(raw_expiration) / 1000,
                    tz=timezone.get_current_timezone(),
                ) - timedelta(seconds=10)
            except (TypeError, ValueError, OverflowError):
                provider_expiry = timezone.now() + timedelta(minutes=3)
            defaults = {
                "wallet": wallet,
                "network": wallet.network,
                "status": TronSendIntent.Status.PREPARED,
                "asset": prepared.asset,
                "sender": prepared.sender,
                "recipient": prepared.recipient,
                "amount": prepared.amount,
                "estimated_fee_trx": prepared.estimated_fee_trx,
                "estimated_energy": prepared.estimated_energy,
                "unsigned_transaction": prepared.unsigned_transaction,
                "expires_at": min(provider_expiry, timezone.now() + timedelta(minutes=10)),
            }
            intent, _created = TronSendIntent.objects.get_or_create(
                user=request.user,
                idempotency_key=form.cleaned_data["idempotency_key"],
                defaults=defaults,
            )
        except (TronSendError, ValueError) as exc:
            form.add_error(None, str(exc))
        except IntegrityError:
            form.add_error(None, "This send request already exists.")
        else:
            return redirect("wallet:tron_send_confirm", intent_id=intent.pk)
    return render(request, "wallet/tron_send_prepare.html", {"wallet": wallet, "sender": sender, "form": form})


@login_required
@require_http_methods(["GET", "POST"])
def tron_send_confirm(request, intent_id: UUID):
    intent = TronSendIntent.objects.select_related("wallet", "network").filter(
        pk=intent_id, user=request.user
    ).first()
    if intent is None:
        raise Http404("Send request not found.")
    if intent.status != TronSendIntent.Status.PREPARED:
        return redirect("wallet:tron_send_result", intent_id=intent.pk)
    session_key = f"tron_send_confirmation:{intent.pk}"
    if request.method == "GET":
        token = secrets.token_urlsafe(32)
        request.session[session_key] = hashlib.sha256(token.encode()).hexdigest()
        form = TronSendConfirmForm(initial={"confirmation_token": token})
    else:
        form = TronSendConfirmForm(request.POST)
        if form.is_valid():
            supplied = hashlib.sha256(form.cleaned_data["confirmation_token"].encode()).hexdigest()
            expected = request.session.pop(session_key, "")
            if not expected or not secrets.compare_digest(supplied, expected):
                form.add_error(None, "Confirmation expired. Review the transaction again.")
            elif not intent.network.is_testnet and not getattr(settings, "TRON_MAINNET_BROADCAST_ENABLED", False):
                form.add_error(None, "TRON mainnet broadcasting is disabled.")
            elif intent.expires_at <= timezone.now():
                intent.status = TronSendIntent.Status.EXPIRED
                intent.save(update_fields=["status", "updated_at"])
                form.add_error(None, "This transaction expired. Prepare a new one.")
            else:
                device = USBDetector().find(form.cleaned_data["usb_device_id"])
                if device is None:
                    form.add_error("usb_device_id", "The selected USB vault is not connected.")
                else:
                    try:
                        secret = USBVault(device).unlock(form.cleaned_data["password"])
                        client = TronSendClient(rpc_url=_tron_rpc_url_for(intent.wallet))
                        signed = client.sign(intent.unsigned_transaction, secret, intent.sender)
                        del secret
                        with transaction.atomic():
                            locked = TronSendIntent.objects.select_for_update().get(pk=intent.pk)
                            if locked.status != TronSendIntent.Status.PREPARED:
                                return redirect("wallet:tron_send_result", intent_id=intent.pk)
                            if locked.expires_at <= timezone.now():
                                locked.status = TronSendIntent.Status.EXPIRED
                                locked.save(update_fields=["status", "updated_at"])
                                raise TronSendError("This transaction expired. Prepare a new one.")
                            locked.status = TronSendIntent.Status.BROADCASTING
                            locked.save(update_fields=["status", "updated_at"])
                        try:
                            txid = client.broadcast(signed, is_testnet=intent.network.is_testnet)
                        finally:
                            del signed
                        intent.status = TronSendIntent.Status.SUBMITTED
                        intent.transaction_hash = txid
                        intent.submitted_at = timezone.now()
                        intent.save(update_fields=["status", "transaction_hash", "submitted_at", "updated_at"])
                        return redirect("wallet:tron_send_result", intent_id=intent.pk)
                    except TronBroadcastUnknown as exc:
                        intent.status = TronSendIntent.Status.OUTCOME_UNKNOWN
                        intent.error_code = "broadcast_outcome_unknown"
                        intent.error_message = str(exc)
                        intent.save(update_fields=["status", "error_code", "error_message", "updated_at"])
                        return redirect("wallet:tron_send_result", intent_id=intent.pk)
                    except (TronBroadcastBlocked, TronSendError, USBVaultError, ValueError) as exc:
                        TronSendIntent.objects.filter(
                            pk=intent.pk,
                            status=TronSendIntent.Status.BROADCASTING,
                        ).update(
                            status=TronSendIntent.Status.REJECTED,
                            error_code="send_rejected",
                            error_message=str(exc)[:255],
                        )
                        form.add_error(None, str(exc))
                    except Exception:
                        form.add_error(None, "Authorization failed. No automatic retry was attempted.")
    return render(request, "wallet/tron_send_confirm.html", {
        "intent": intent,
        "form": form,
        "usb_vaults": _available_usb_vaults(),
        "mainnet_blocked": not intent.network.is_testnet and not getattr(settings, "TRON_MAINNET_BROADCAST_ENABLED", False),
    })


@login_required
@require_GET
def tron_send_result(request, intent_id: UUID):
    intent = TronSendIntent.objects.select_related("network").filter(pk=intent_id, user=request.user).first()
    if intent is None:
        raise Http404("Send request not found.")
    return render(request, "wallet/tron_send_result.html", {"intent": intent})


# ============================================================================
# WALLET CREATION
# ============================================================================


@login_required
def create_wallet(request):
    """
    Create a new encrypted wallet.

    Wallet generation and secret persistence are delegated to
    WalletCreationService.
    """

    if _get_user_wallet(request.user) is not None:
        messages.info(
            request,
            "You already have a wallet.",
        )
        return redirect("wallet:home")

    form = CreateWalletForm(
        request.POST or None,
    )

    if request.method != "POST" or not form.is_valid():
        return render(
            request,
            "wallet/create.html",
            {
                "form": form,
            },
        )

    network = (
        BlockchainNetwork.objects
        .filter(
            slug=DEFAULT_NETWORK_SLUG,
            is_active=True,
            is_testnet=False,
        )
        .first()
    )

    if network is None:
        form.add_error(
            None,
            "Ethereum Mainnet is not available.",
        )

        return render(
            request,
            "wallet/create.html",
            {
                "form": form,
            },
        )

    try:
        WalletCreationService().create_wallet(
            user=request.user,
            network=network,
            password=form.cleaned_data["password"],
        )

    except WalletCreationError as exc:
        form.add_error(
            None,
            str(exc),
        )

    except Exception:
        form.add_error(
            None,
            "Wallet creation failed. Please try again.",
        )

    else:
        messages.success(
            request,
            (
                "Wallet created successfully. "
                "Your wallet is currently locked."
            ),
        )

        return redirect("wallet:home")

    return render(
        request,
        "wallet/create.html",
        {
            "form": form,
        },
    )


# ============================================================================
# WALLET UNLOCK
# ============================================================================


@login_required
def unlock_wallet(request):
    """
    Unlock the authenticated user's wallet.

    Security boundary
    -----------------

    The view:

    - accepts only the wallet password
    - delegates vault verification/decryption to WalletVaultService
    - never stores decrypted wallet secrets
    - never places secrets in the session
    - never renders secrets
    - never logs secrets
    - activates the wallet only after successful vault decryption

    Wallet lifecycle state is managed by WalletService.
    """

    wallet = _get_user_wallet(request.user)

    if wallet is None:
        messages.error(
            request,
            "You do not have a wallet.",
        )
        return redirect("wallet:create")

    if wallet.status == Wallet.Status.ACTIVE:
        messages.info(
            request,
            "Your wallet is already unlocked.",
        )
        return redirect("wallet:home")

    form = UnlockWalletForm(
        request.POST or None,
    )

    if request.method == "POST" and form.is_valid():
        password = form.cleaned_data["password"]

        try:
            # Successful decryption proves that the supplied
            # password can open the wallet vault.
            secret = WalletVaultService().open_secret(
                wallet=wallet,
                password=password,
            )

            # The decrypted secret is intentionally not used by this
            # HTTP operation and must never leave this scope.
            del secret

        except InvalidPasswordError:
            form.add_error(
                "password",
                "Incorrect wallet password.",
            )

        except ValueError as exc:
            form.add_error(
                None,
                str(exc),
            )

        except Exception:
            form.add_error(
                None,
                "Unable to unlock wallet. Please try again.",
            )

        else:
            # Wallet lifecycle state is owned by WalletService.
            WalletService.activate_wallet(wallet)

            messages.success(
                request,
                "Wallet unlocked successfully.",
            )

            return redirect("wallet:home")

    return render(
        request,
        "wallet/unlock.html",
        {
            "form": form,
            "wallet": wallet,
        },
    )

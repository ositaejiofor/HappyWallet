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

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import redirect, render

from apps.blockchain.models import BlockchainNetwork
from apps.security.vault import InvalidPasswordError
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
    UnlockWalletForm,
)
from .services.wallet import WalletService


APP_NAME = "HappyWallet"
DEFAULT_NETWORK_SLUG = "ethereum-mainnet"


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
        **selection_context,
        **_wallet_status_context(wallet),
    }

    return render(
        request,
        "wallet/home.html",
        context,
    )


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

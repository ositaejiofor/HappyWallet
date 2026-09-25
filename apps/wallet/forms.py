"""
HappyWallet wallet forms.

Security boundary
-----------------

This module validates user input for wallet operations.

This module:

- accepts wallet passwords only
- never accepts recovery phrases
- never generates recovery phrases
- never accepts private keys
- never handles seed material
- never performs wallet derivation
- never persists wallet secrets

Wallet generation, encryption, decryption, and secure persistence are
handled by the appropriate application/security services.
"""

from __future__ import annotations

from django import forms
import uuid


# ============================================================================
# SHARED PASSWORD FIELD
# ============================================================================


class WalletPasswordField(forms.CharField):
    """
    Shared password field for wallet creation and wallet unlocking.

    This field is responsible only for HTTP form validation and presentation.
    It never performs password verification or cryptographic operations.
    """

    def __init__(
        self,
        *,
        label: str = "Wallet Password",
        placeholder: str = "Enter your wallet password",
        autocomplete: str = "current-password",
        **kwargs,
    ) -> None:
        error_messages = {
            "required": "Wallet password is required.",
        }

        supplied_errors = kwargs.pop(
            "error_messages",
            None,
        )

        if supplied_errors:
            error_messages.update(
                supplied_errors,
            )

        super().__init__(
            label=label,
            required=True,
            strip=False,
            widget=forms.PasswordInput(
                attrs={
                    "class": "form-control",
                    "placeholder": placeholder,
                    "autocomplete": autocomplete,
                }
            ),
            error_messages=error_messages,
            **kwargs,
        )


# ============================================================================
# CREATE WALLET
# ============================================================================


class CreateWalletForm(forms.Form):
    """
    Validate the password required to create a new wallet.

    The form does not generate, derive, decrypt, or persist wallet secrets.
    """

    password = WalletPasswordField(
        label="Wallet Password",
        placeholder="Create a strong wallet password",
        autocomplete="new-password",
        min_length=8,
        error_messages={
            "required": "Wallet password is required.",
            "min_length": (
                "Wallet password must contain at least 8 characters."
            ),
        },
    )

    password_confirm = WalletPasswordField(
        label="Confirm Wallet Password",
        placeholder="Repeat your wallet password",
        autocomplete="new-password",
    )

    def clean(self):
        """
        Ensure both wallet password fields match.
        """

        cleaned_data = super().clean()

        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if (
            password
            and password_confirm
            and password != password_confirm
        ):
            self.add_error(
                "password_confirm",
                "The wallet passwords do not match.",
            )

        return cleaned_data


# ============================================================================
# UNLOCK WALLET
# ============================================================================


class UnlockWalletForm(forms.Form):
    """
    Validate the password used to unlock an existing wallet.

    This form does not decrypt the wallet and does not access wallet
    secrets. Password verification and vault decryption are delegated
    to WalletVaultService.
    """

    password = WalletPasswordField(
        label="Wallet Password",
        placeholder="Enter your wallet password",
        autocomplete="current-password",
    )


class TronSendPrepareForm(forms.Form):
    asset = forms.ChoiceField(choices=(("TRX", "TRX"), ("USDT", "USDT (TRC-20)")))
    recipient = forms.CharField(max_length=64)
    amount = forms.DecimalField(max_digits=36, decimal_places=6, min_value=0)
    idempotency_key = forms.UUIDField(widget=forms.HiddenInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.is_bound:
            self.initial["idempotency_key"] = uuid.uuid4()


class TronSendConfirmForm(forms.Form):
    confirmation_token = forms.CharField(widget=forms.HiddenInput)
    usb_device_id = forms.CharField(max_length=255)
    password = WalletPasswordField()
    final_confirmation = forms.BooleanField(
        label="I verified the network, recipient, asset, amount, and estimated fee.",
        required=True,
    )


# ============================================================================
# PUBLIC API
# ============================================================================


__all__ = [
    "CreateWalletForm",
    "UnlockWalletForm",
    "WalletPasswordField",
    "TronSendPrepareForm",
    "TronSendConfirmForm",
]

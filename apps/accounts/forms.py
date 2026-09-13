# apps/accounts/forms.py

"""
HappyWallet account forms.

Provides authentication, registration, account-information updates,
and secure password changes for the custom email-based User model.
"""

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    UserCreationForm,
)
from django.core.exceptions import ValidationError

from .models import User


FORM_CONTROL_CLASS = "form-control"


class LoginForm(AuthenticationForm):
    """
    Authenticate a HappyWallet user using email and password.
    """

    username = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your email address",
                "autocomplete": "email",
                "autofocus": True,
            }
        ),
    )

    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your password",
                "autocomplete": "current-password",
            }
        ),
    )

    def clean(self):
        """
        Normalize the email and authenticate the supplied credentials.
        """
        email = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")

        if email:
            email = email.strip().lower()
            self.cleaned_data["username"] = email

        if email and password:
            self.user_cache = authenticate(
                self.request,
                email=email,
                password=password,
            )

            if self.user_cache is None:
                raise self.get_invalid_login_error()

            self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data


class RegistrationForm(UserCreationForm):
    """
    Create a HappyWallet user using Django's password validation
    and secure password-hashing system.
    """

    password1 = forms.CharField(
        label="Password",
        strip=False,
        help_text=(
            "Use at least 12 characters and avoid common or easily "
            "guessed passwords."
        ),
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Create a secure password",
                "autocomplete": "new-password",
            }
        ),
    )

    password2 = forms.CharField(
        label="Confirm password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Confirm your password",
                "autocomplete": "new-password",
            }
        ),
    )

    class Meta:
        model = User

        fields = [
            "email",
            "username",
        ]

        widgets = {
            "email": forms.EmailInput(
                attrs={
                    "class": FORM_CONTROL_CLASS,
                    "placeholder": "Enter your email address",
                    "autocomplete": "email",
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": FORM_CONTROL_CLASS,
                    "placeholder": "Choose a username",
                    "autocomplete": "username",
                }
            ),
        }

    def clean_email(self):
        """
        Normalize the email address and validate case-insensitive
        uniqueness.
        """
        email = self.cleaned_data["email"].strip().lower()

        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError(
                "An account with this email address already exists."
            )

        return email

    def clean_username(self):
        """
        Normalize the username and validate case-insensitive uniqueness.
        """
        username = self.cleaned_data["username"].strip()

        if not username:
            raise ValidationError(
                "Username is required."
            )

        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError(
                "This username is already in use."
            )

        return username


class AccountUpdateForm(forms.ModelForm):
    """
    Update an existing HappyWallet user's username and email address.
    """

    class Meta:
        model = User

        fields = [
            "username",
            "email",
        ]

        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": FORM_CONTROL_CLASS,
                    "placeholder": "Enter your username",
                    "autocomplete": "username",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": FORM_CONTROL_CLASS,
                    "placeholder": "Enter your email address",
                    "autocomplete": "email",
                }
            ),
        }

    def clean_email(self):
        """
        Normalize the email and ensure another account does not use it.
        """
        email = self.cleaned_data["email"].strip().lower()

        email_exists = (
            User.objects
            .filter(email__iexact=email)
            .exclude(pk=self.instance.pk)
            .exists()
        )

        if email_exists:
            raise ValidationError(
                "Another account already uses this email address."
            )

        return email

    def clean_username(self):
        """
        Normalize the username and ensure another account does not use it.
        """
        username = self.cleaned_data["username"].strip()

        if not username:
            raise ValidationError(
                "Username is required."
            )

        username_exists = (
            User.objects
            .filter(username__iexact=username)
            .exclude(pk=self.instance.pk)
            .exists()
        )

        if username_exists:
            raise ValidationError(
                "Another account already uses this username."
            )

        return username


class AccountPasswordChangeForm(PasswordChangeForm):
    """
    Securely change an authenticated HappyWallet user's password.

    Django validates the current password, checks that both new-password
    fields match, applies configured password validators, and hashes the
    new password before saving it.
    """

    old_password = forms.CharField(
        label="Current password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your current password",
                "autocomplete": "current-password",
                "autofocus": True,
            }
        ),
    )

    new_password1 = forms.CharField(
        label="New password",
        strip=False,
        help_text=(
            "Use at least 12 characters and avoid common or easily "
            "guessed passwords."
        ),
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your new password",
                "autocomplete": "new-password",
            }
        ),
    )

    new_password2 = forms.CharField(
        label="Confirm new password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Confirm your new password",
                "autocomplete": "new-password",
            }
        ),
    )
    
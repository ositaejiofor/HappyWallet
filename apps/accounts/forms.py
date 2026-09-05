# apps/accounts/forms.py

"""
HappyWallet Account Forms

Authentication and registration forms for the custom
email-based User model.
"""

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError

from .models import User


class LoginForm(AuthenticationForm):
    """
    Authenticate a HappyWallet user using email and password.

    Authentication is delegated to Django's configured
    authentication backend.
    """

    username = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your email",
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
                "class": "form-control",
                "placeholder": "Enter your password",
                "autocomplete": "current-password",
            }
        ),
    )

    def clean(self):
        """
        Authenticate the supplied email and password.
        """

        email = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")

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

    def get_user(self):
        return self.user_cache


class RegistrationForm(forms.ModelForm):
    """
    Create a new HappyWallet account.

    Passwords are passed to Django's password hashing system
    and are never stored as plain text.
    """

    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Create a password",
                "autocomplete": "new-password",
            }
        ),
    )

    password2 = forms.CharField(
        label="Confirm password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
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
                    "class": "form-control",
                    "placeholder": "Enter your email",
                    "autocomplete": "email",
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Choose a username",
                    "autocomplete": "username",
                }
            ),
        }

    def clean_email(self):
        """
        Normalize and validate the email address.
        """

        email = self.cleaned_data["email"].strip().lower()

        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError(
                "An account with this email address already exists."
            )

        return email

    def clean_username(self):
        """
        Validate username uniqueness.
        """

        username = self.cleaned_data["username"].strip()

        if not username:
            raise ValidationError(
                "Username is required."
            )

        if User.objects.filter(
            username__iexact=username
        ).exists():
            raise ValidationError(
                "This username is already in use."
            )

        return username

    def clean(self):
        """
        Validate that both password fields match.
        """

        cleaned_data = super().clean()

        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            self.add_error(
                "password2",
                "The two passwords do not match.",
            )

        return cleaned_data

    def save(self, commit=True):
        """
        Create the user using Django's password hashing.
        """

        user = super().save(commit=False)

        password = self.cleaned_data["password1"]

        user.set_password(password)

        if commit:
            user.save()

        return user
# apps/accounts/models.py

"""
HappyWallet Accounts Models

Custom authentication model for HappyWallet.

Email is the primary authentication identifier.
"""

import uuid

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom HappyWallet user model.

    Email is used as the authentication identifier.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    email = models.EmailField(
        unique=True,
        db_index=True,
    )

    username = models.CharField(
        max_length=150,
        unique=True,
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
    )

    is_staff = models.BooleanField(
        default=False,
    )

    is_verified = models.BooleanField(
        default=False,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    objects = UserManager()

    # Authentication configuration
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        db_table = "accounts_user"
        ordering = ["-created_at"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    def get_full_name(self):
        """
        Return the user's username as their display name.
        """
        return self.username

    def get_short_name(self):
        """
        Return the user's username.
        """
        return self.username

    @property
    def is_verified_user(self):
        """
        Convenience property for checking account verification.
        """
        return self.is_verified

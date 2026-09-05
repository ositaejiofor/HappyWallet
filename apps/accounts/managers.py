# apps/accounts/managers.py

"""
Custom user manager for HappyWallet.

The User model authenticates users with email addresses instead
of Django's default username authentication.
"""

from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """
    Manager for the HappyWallet custom User model.
    """

    use_in_migrations = True

    def create_user(
        self,
        email,
        username,
        password=None,
        **extra_fields,
    ):
        """
        Create and save a normal HappyWallet user.
        """

        if not email:
            raise ValueError("The email address is required.")

        if not username:
            raise ValueError("The username is required.")

        email = self.normalize_email(email).strip()
        username = username.strip()

        if not email:
            raise ValueError("The email address cannot be empty.")

        if not username:
            raise ValueError("The username cannot be empty.")

        user = self.model(
            email=email,
            username=username,
            **extra_fields,
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)

        return user

    def create_superuser(
        self,
        email,
        username,
        password=None,
        **extra_fields,
    ):
        """
        Create and save a HappyWallet superuser.
        """

        if not password:
            raise ValueError(
                "A password is required for a superuser."
            )

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(
                "Superuser must have is_staff=True."
            )

        if extra_fields.get("is_superuser") is not True:
            raise ValueError(
                "Superuser must have is_superuser=True."
            )

        if extra_fields.get("is_active") is not True:
            raise ValueError(
                "Superuser must have is_active=True."
            )

        return self.create_user(
            email=email,
            username=username,
            password=password,
            **extra_fields,
        )

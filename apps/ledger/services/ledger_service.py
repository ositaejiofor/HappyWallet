from decimal import Decimal

from django.db import transaction
from django.core.exceptions import ValidationError

from apps.ledger.models import LedgerAccount, LedgerEntry


class LedgerService:
    """
    Central accounting service.

    All balance-changing operations should go through this service.
    """

    @staticmethod
    @transaction.atomic
    def transfer(
        *,
        debit_account: LedgerAccount,
        credit_account: LedgerAccount,
        amount: Decimal,
        reference: str,
        description: str = "",
    ):
        """
        Transfer an amount between two ledger accounts.

        Creates exactly two entries:
            DEBIT  -> source account
            CREDIT -> destination account
        """

        amount = Decimal(amount)

        if amount <= 0:
            raise ValidationError(
                "Transfer amount must be greater than zero."
            )

        if debit_account.pk == credit_account.pk:
            raise ValidationError(
                "Debit and credit accounts must be different."
            )

        if debit_account.asset != credit_account.asset:
            raise ValidationError(
                "Debit and credit accounts must use the same asset."
            )

        if not debit_account.is_active:
            raise ValidationError(
                "Debit account is inactive."
            )

        if not credit_account.is_active:
            raise ValidationError(
                "Credit account is inactive."
            )

        if not reference:
            raise ValidationError(
                "A ledger reference is required."
            )

        debit_entry = LedgerEntry.objects.create(
            account=debit_account,
            entry_type=LedgerEntry.EntryType.DEBIT,
            amount=amount,
            reference=reference,
            description=description,
        )

        credit_entry = LedgerEntry.objects.create(
            account=credit_account,
            entry_type=LedgerEntry.EntryType.CREDIT,
            amount=amount,
            reference=reference,
            description=description,
        )

        return debit_entry, credit_entry

    @staticmethod
    def balance(account: LedgerAccount) -> Decimal:
        """
        Calculate the current balance of an account.

        Asset accounts:
            credits - debits

        Other account types:
            debits - credits
        """

        entries = LedgerEntry.objects.filter(
            account=account
        ).values_list(
            "entry_type",
            "amount",
        )

        debit_total = Decimal("0")
        credit_total = Decimal("0")

        for entry_type, amount in entries:
            if entry_type == LedgerEntry.EntryType.DEBIT:
                debit_total += amount
            else:
                credit_total += amount

        if account.account_type == LedgerAccount.AccountType.ASSET:
            return credit_total - debit_total

        return debit_total - credit_total

    @staticmethod
    def account_balance(
        *,
        wallet,
        asset: str,
    ) -> Decimal:
        """
        Return the balance for a wallet/asset pair.
        """

        account = LedgerAccount.objects.filter(
            wallet=wallet,
            asset=asset,
            account_type=LedgerAccount.AccountType.ASSET,
            is_active=True,
        ).first()

        if account is None:
            return Decimal("0")

        return LedgerService.balance(account)
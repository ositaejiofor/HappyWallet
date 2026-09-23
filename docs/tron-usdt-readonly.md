# Read-only TRON USDT support

This milestone adds public TRC-20 USDT balances and confirmed transfer history
without adding transaction construction, signing, private-key access, or
broadcasting.

## Install

After applying the patch, run:

```bash
python manage.py provision_networks
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test \
  apps.wallet.test_tron_balance \
  apps.wallet.test_wallet_selection \
  apps.transaction.tests.tests_tron_history \
  apps.transaction.tests.tests_history
```

Restart the Django server, select the TRON wallet, and refresh the Wallet and
Transactions pages.

## Configuration

The public TronGrid endpoint remains `https://api.trongrid.io`. A TronGrid API
key may be provided with `TRON_API_KEY` for provider quotas. It is not a wallet
key and cannot sign transactions.

`TRON_USDT_CONTRACT_ADDRESS` defaults to the official TRON Mainnet Tether USD
contract:

```text
TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
```

The provisioning command creates or updates the matching active TRC-20 Asset
record with 6 decimals. Re-running the command is idempotent.

## Safety boundary

- Queries confirmed public account state and transaction history only.
- Keeps TRX and USDT balances separate.
- Disables the Send action for TRON wallets.
- Does not request, store, decrypt, or expose private keys or recovery phrases.
- Does not construct, sign, or broadcast TRON transactions.
- Bounds network timeouts, retries, response size, decimals, and history size.

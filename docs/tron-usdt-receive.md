# Production-safe USDT TRC-20 receive flow

This milestone adds a receive-only experience for an active, owned TRON
wallet. It does not add transaction construction, signing, or broadcasting.

## Features

- Locally generated SVG QR code for the public TRON address.
- Explicit `USDT — TRON (TRC-20)` network identity.
- Official USDT contract displayed beside the receiving address.
- Read-only confirmed incoming-deposit status.
- Link to the wallet-scoped confirmed transaction history.
- Ownership, active-wallet, TRON-network, address, and HTTP-method checks.
- `no-store` and `nosniff` response headers on receive endpoints.

## Install and verify

```bash
pip install -r requirements.txt
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test \
  apps.wallet.test_tron_receive \
  apps.wallet.test_tron_balance \
  apps.wallet.test_wallet_selection \
  apps.transaction.tests.tests_tron_history
```

Restart the server, select the TRON wallet, and choose **Receive**. Before a
Bybit withdrawal, verify all of the following independently:

1. Asset: USDT.
2. Network: TRON (TRC-20).
3. Destination address exactly matches the written HappyWallet address.
4. Contract: `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`.

Start with a small test withdrawal. A provider may report a withdrawal before
TronGrid reports it as confirmed; HappyWallet displays confirmed history only.

## Security boundary

The QR code contains only the public receiving address. HappyWallet does not
send the address to a third-party QR service. These endpoints cannot unlock a
wallet, access secret material, build a transfer, sign, or broadcast.

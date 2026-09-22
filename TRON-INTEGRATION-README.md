# HappyWallet public TRX integration

This package adds native public TRX balances to the Wallet page and confirmed
native TRX transfer history to the Transactions page.

## Security boundary

- Uses public wallet addresses only.
- Reads only confirmed, indexed TronGrid history.
- Never reads private keys, mnemonics, seeds, or signing material.
- Never constructs, signs, or broadcasts a transaction.
- Keeps `TronBroadcaster` fail-closed.
- Ignores TRC-10/TRC-20 token balances for this milestone.

## Install

From the HappyWallet repository root, extract this package so that its `apps`
directory merges with the existing `apps` directory. Existing versions of
these three files are replaced:

- `apps/transaction/services/networks/tron.py`
- `apps/transaction/services/history.py`
- `apps/wallet/services/wallet_balance.py`

These files are new:

- `apps/wallet/services/tron_balance.py`
- `apps/transaction/tests/tests_tron_history.py`
- `apps/wallet/test_tron_balance.py`

No template or view change is required. Both pages already consume the common
application DTOs used by this integration.

## Configuration

Keep the existing values:

```dotenv
TRON_RPC_URL=https://api.trongrid.io
TRON_API_KEY=your_trongrid_key
TRON_RPC_TIMEOUT=10
```

The transaction history limit defaults to 25 and is bounded to TronGrid's
maximum of 200. No new setting is required.

## Verify

```bash
python -m py_compile \
  apps/transaction/services/networks/tron.py \
  apps/transaction/services/history.py \
  apps/wallet/services/tron_balance.py \
  apps/wallet/services/wallet_balance.py \
  apps/transaction/tests/tests_tron_history.py \
  apps/wallet/test_tron_balance.py

python manage.py check

python manage.py test \
  apps.transaction.tests.tests_tron \
  apps.transaction.tests.tests_tron_history \
  apps.transaction.tests.tests_history \
  apps.wallet.test_tron_balance
```

Then open a wallet configured with `tron-mainnet` and a valid public TRON
address. Visit:

- `http://127.0.0.1:9000/wallet/`
- `http://127.0.0.1:9000/transactions/`

If a provider request fails, the pages remain usable and display the existing
unavailable state instead of treating the failure as a confirmed zero balance.

# Guarded TRON sends

HappyWallet can prepare and authorize native TRX and configured TRC-20 USDT
transfers. The workflow is intentionally testnet-first.

## Safety sequence

1. The server validates the Base58Check recipient, amount precision, asset,
   live balances, and the TRX fee reserve.
2. TronGrid constructs an unsigned transaction. HappyWallet independently
   verifies its transaction ID and checks that its decoded sender, recipient,
   asset, and amount still match the user's request.
3. USDT is simulated with `triggerconstantcontract`; the displayed fee has a
   configurable safety margin. Estimates are not guarantees.
4. The user reviews a separate final-confirmation screen and must connect a
   complete encrypted HappyWallet USB vault, enter its password, and confirm
   every transaction field.
5. The private key and signed transaction exist only in process memory. They
   are not stored in the database, session, template, or logs.
6. `(user, idempotency_key)` is unique. The authorization token is single-use,
   and the intent is locked and moved to `broadcasting` before the one allowed
   broadcast call.
7. A transport failure becomes `outcome_unknown`; HappyWallet never retries it
   automatically.

## Environment

```dotenv
TRON_TESTNET_RPC_URL=https://api.shasta.trongrid.io
TRON_TESTNET_BROADCAST_ENABLED=True

# Configure the exact Shasta test token contract you obtained from the faucet.
# Never put the mainnet USDT contract here.
TRON_TESTNET_USDT_CONTRACT_ADDRESS=

# Keep false until a separate production security review is complete.
TRON_MAINNET_BROADCAST_ENABLED=False

TRON_TRX_FEE_RESERVE=1.100000
TRON_USDT_MIN_FEE_RESERVE=30
TRON_ENERGY_PRICE_SUN=420
TRON_FEE_SAFETY_MULTIPLIER=1.20
```

Run `python manage.py provision_networks`, create/import a wallet whose public
address is derived from the connected USB vault for `TRON Shasta Testnet`, and
fund it only with faucet assets. A Shasta USDT send remains unavailable until
`TRON_TESTNET_USDT_CONTRACT_ADDRESS` is set to the exact test-token contract.

Do not enable mainnet merely because tests pass. Confirm resource pricing,
limits, monitoring, solidified-chain reconciliation, backups, incident
procedures, and an independent security review first.

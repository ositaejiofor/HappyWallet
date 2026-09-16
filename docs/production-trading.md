# HappyWallet production trading checklist

HappyWallet remains paper-first. A deployment must pass every item below before
an administrator changes a user's trading account to `Live Trading`.

## Kraken API key

- Create a dedicated Kraken API key for HappyWallet.
- Enable only the permissions required to query balances/orders and place or
  cancel spot orders.
- Disable withdrawals and funding permissions.
- Apply Kraken IP restrictions where the hosting platform has stable egress IPs.
- Store the key and base64 API secret in the deployment secret manager, never
  in Git, a ZIP archive, browser storage, or a Django template.
- Rotate the key immediately if it is ever exposed.

## Fail-closed configuration

Keep these environment variables until mocked tests and a validation-only
exchange check have passed:

```text
KRAKEN_LIVE_TRADING_ENABLED=false
WALLET_REQUIRE_CONFIRMATION=true
```

Only the production operator may later set:

```text
KRAKEN_API_KEY=<secret-manager-reference>
KRAKEN_API_SECRET=<secret-manager-reference>
KRAKEN_LIVE_TRADING_ENABLED=true
```

The account must also be active and explicitly changed to `Live Trading` in the
admin. All four conditions are required before the live confirmation control is
shown.

## Deployment

- Use PostgreSQL with TLS, HTTPS, secure cookies, HSTS and trusted proxy headers.
- Run `python manage.py check --deploy --settings=config.settings.production`.
- Run migrations and `collectstatic` during a controlled release.
- Use a single authoritative time source and monitor clock drift; Kraken private
  requests require increasing nonces.
- Run more than one process only after nonce generation is coordinated across
  processes. The current adapter's nonce counter is process-local.
- Restrict admin access, require strong authentication, and retain audit logs.
- Alert on `SUBMITTING` or `UNKNOWN` orders and reconcile them before any retry.
- Back up the production database and test restoration.

## Order workflow

1. A live account creates a local `PENDING` intent.
2. The user reviews the order, checks the risk box and types `PLACE LIVE ORDER`.
3. HappyWallet persists `SUBMITTING` before the network request.
4. A definite rejection becomes `REJECTED`.
5. A transport or malformed-response outcome becomes `UNKNOWN`; never retry it
   automatically.
6. Read-only reconciliation searches Kraken by deterministic client order ID.
7. Kraken acceptance becomes `OPEN`; it does not mean the order is filled.

## Important limitation

The web application intentionally refuses to mark a submitted live order as
cancelled only in its local database. Exchange cancellation must be implemented
and verified against Kraken before a live cancel button is offered. Until then,
cancel submitted orders at Kraken and reconcile HappyWallet afterward.

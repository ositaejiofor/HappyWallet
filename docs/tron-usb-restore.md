# Restore a TRON Shasta USB vault

This recovery flow is only for an existing HappyWallet TRON Shasta wallet whose
public address is already stored in the database.

The command reads the 24-word recovery phrase through a hidden terminal prompt.
It derives the TRON address before writing anything and refuses to continue
unless that address exactly matches the selected wallet. It never prints the
phrase or stores it in the database.

Run from the HappyWallet project with the removable USB inserted:

```bash
python manage.py restore_tron_testnet_usb \
  --device "E:" \
  --username "EAGLE-TECH" \
  --wallet-id "cd96fb52-c242-412f-899d-31a3ab37d0d7"
```

Enter the recovery words only at the hidden prompt. Never paste them into chat,
a normal shell command, a source file, or an environment file.

The command refuses to overwrite any complete or partial HappyWallet vault on
the selected USB. After creating the encrypted files, it decrypts them once and
verifies the derived address again.

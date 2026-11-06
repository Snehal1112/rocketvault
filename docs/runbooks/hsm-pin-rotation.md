# Runbook: Rotating the SoftHSM2 Token PIN

`.rocketvault.yaml`'s `hsm.pin` authenticates to the real SoftHSM2 (or other
PKCS#11) token named by `hsm.token_label`. **Editing the config value alone
does nothing** — PIN state lives in the token itself, not in RocketVault. If
you change `hsm.pin` in config without also changing the token's real PIN,
every HSM-routed key operation starts failing to authenticate.

This is why rotation is a manual, human-run procedure and not a CLI command:
the token may be shared with other software or other RocketVault instances,
and re-initializing it destroys every key it holds unless you use the
PIN-change form specifically (not `--init-token`, which wipes the token).

## 1. Confirm what uses this token

```bash
grep -A5 '^hsm:' .rocketvault.yaml
```

Note `token_label` and `slot_id`. If anything other than this RocketVault
instance uses the same token (shared SoftHSM2 install, another service), you
must coordinate with it before changing the PIN — its config needs the new PIN
too, at the same time, or it starts failing.

## 2. Stop RocketVault

Concurrent HSM operations during a PIN change can fail loudly (safe) but there
is no reason to risk it — stop the server first.

## 3. Change the token's PIN (not re-init)

```bash
softhsm2-util --pin '<current PIN>' --new-pin '<new PIN>' --token-label rocketvault
```

Use a freshly generated PIN, not something typed by hand:

```bash
openssl rand -base64 18 | tr -d '=+/' | head -c 24
```

**Do not use `softhsm2-util --init-token`** for this — that wipes every key
the token holds. `--pin ... --new-pin ...` changes the PIN of the existing
token in place, keeping its keys.

## 4. Update `.rocketvault.yaml`

```bash
sed -i "s#^  pin: .*#  pin: \"<new PIN>\"#" .rocketvault.yaml
```

(Indentation must match the existing `hsm:` block — it is a nested key, not
top-level.)

## 5. Restart and verify

```bash
./rocketvault serve
./rocketvault keys list --vault default
```

A successful list proves the new PIN authenticates. If it fails with a PKCS#11
authentication error, the token still has the old PIN, or step 3 targeted the
wrong `--token-label` — check `softhsm2-util --show-slots` to confirm the
token label and slot actually changed.

## 6. If something goes wrong

| Symptom | Cause | Action |
|---|---|---|
| `CKR_PIN_INCORRECT` after restart | Config and token PIN disagree | Re-run step 3 with the PIN you actually set, or step 4 with the PIN you actually changed to — whichever was mistyped. |
| `softhsm2-util --pin` itself fails | Wrong current PIN, or wrong `--token-label` | `softhsm2-util --show-slots` to find the real label; retry with the correct current PIN. |
| Other software using the same token now fails | This token is shared and its config wasn't updated | Update that software's PIN config too — this is why step 1's coordination check matters. |

## Never do this

- Never commit a PIN — real or placeholder — into any tracked file. The
  previous PIN (`1234`) was committed in `.rocketvault.yaml` for 5+ months
  (`docs/known-bugs.md` § B10) and must be treated as permanently
  compromised even after this rotation.
- Never reuse an old, possibly-compromised PIN as the "new" PIN.

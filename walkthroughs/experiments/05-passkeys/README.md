# Experiment 5: Passkeys — Sync vs Device-Bound + Attestation

A passkey is a discoverable credential. Where the key lives determines what the RP can trust. This experiment builds on Experiment 3 (WebAuthn Ceremonies) to explore passkey-specific concepts: discoverable vs non-discoverable credentials, synced vs device-bound, backup flags (BE/BS), conditional UI, hybrid transport, and enterprise credential policy.

## Layer

**Presence** — How does the system know a human is present, and WHICH human? (WebAuthn, passkeys, FIDO2, attestation)

## What you'll learn

- Discoverable vs non-discoverable credentials (residentKey)
- Backup flags (BE/BS) — what they tell the RP about credential storage
- Synced passkey registration (iCloud Keychain) — "none" attestation, cloud recovery
- Device-bound registration (YubiKey) — "packed" attestation, hardware assurance
- Passkey authentication with conditional UI (autofill dropdown)
- Credential Registration Policy Lab — 5 scenarios covering synced, hardware, platform, hybrid, and enterprise policy

## How to run

```bash
npm install && node run.js
```

Interactive mode steps through one screen at a time. Press ENTER to advance.

For a full dump (all scenarios, no pausing):

```bash
node run.js --no-pause
```

## Estimated time

~20 minutes

## After running, you should be able to:

- Distinguish discoverable (resident) from non-discoverable credentials and when each is appropriate
- Read the BE/BS backup flags and explain what each combination means for the RP's trust model
- Compare synced passkeys (cloud recovery, "none" attestation) vs device-bound (hardware assurance, "packed" attestation)
- Explain conditional UI and how the browser autofill dropdown replaces "Sign in with passkey" buttons
- Design a credential registration policy that handles synced, hardware, platform, and enterprise requirements

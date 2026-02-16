# Experiment 5: Passkeys — Sync vs Device-Bound + Attestation

**Layer:** Presence

A passkey is a discoverable credential. Where the key lives determines what the RP can trust. This experiment builds on Experiment 3 (WebAuthn Ceremonies) to explore passkey-specific concepts: discoverable vs non-discoverable credentials, synced vs device-bound, backup flags (BE/BS), conditional UI, hybrid transport, and enterprise credential policy.

## Run

```bash
npm install
node run.js            # Interactive — step through with ENTER
node run.js --no-pause # Full dump — all scenarios, no pauses
```

## What You'll Learn

- Discoverable vs non-discoverable credentials (residentKey)
- Backup flags (BE/BS) — what they tell the RP about credential storage
- Synced passkey registration (iCloud Keychain) — "none" attestation, cloud recovery
- Device-bound registration (YubiKey) — "packed" attestation, hardware assurance
- Passkey authentication with conditional UI (autofill dropdown)
- Credential Registration Policy Lab — 5 scenarios covering synced, hardware, platform, hybrid, and enterprise policy

## Dependencies

- `cbor-x` — CBOR encoding for COSE keys and attestation objects
- Node `crypto` — key generation, SHA-256, signing (no external deps needed)

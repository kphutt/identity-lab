# Experiment 3: WebAuthn Ceremonies — Registration + Authentication

**Layer:** Presence

WebAuthn replaces passwords with public-key cryptography. The browser mediates between the website (Relying Party) and the authenticator (USB key, platform biometric, phone), providing phishing resistance by binding credentials to the origin.

## Run

```bash
npm install
node run.js            # Interactive — step through with ENTER
node run.js --no-pause # Full dump — all scenarios, no pauses
```

## What You'll Learn

- PublicKeyCredentialCreationOptions — every field annotated
- authenticatorData binary layout — byte-by-byte with hex dump
- clientDataJSON — the browser's phishing defense (origin binding)
- attestationObject — CBOR-encoded attestation (none vs packed)
- Authentication ceremony — signature verification step by step
- RP Configuration Lab — UV required/discouraged, attestation modes, clone detection

## Dependencies

- `jose` — JWK export for COSE↔JWK educational bridge
- `cbor-x` — CBOR encoding/decoding for COSE keys and attestation objects
- Node `crypto` — SHA-256, ECDSA sign/verify, key generation

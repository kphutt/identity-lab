# Experiment 3: WebAuthn Ceremonies — Registration + Authentication

WebAuthn replaces passwords with public-key cryptography. The browser mediates between the website (Relying Party) and the authenticator (USB key, platform biometric, phone), providing phishing resistance by binding credentials to the origin. This experiment walks through both ceremonies byte by byte.

## Layer

**Presence** — How does the system know a human is present, and WHICH human? (WebAuthn, passkeys, FIDO2, attestation)

## What you'll learn

- PublicKeyCredentialCreationOptions — every field annotated
- authenticatorData binary layout — byte-by-byte with hex dump
- clientDataJSON — the browser's phishing defense (origin binding)
- attestationObject — CBOR-encoded attestation (none vs packed)
- Authentication ceremony — signature verification step by step
- RP Configuration Lab — UV required/discouraged, attestation modes, clone detection

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

~25 minutes

## After running, you should be able to:

- Explain the WebAuthn registration ceremony and what each field in the attestation response contains
- Parse authenticatorData bytes and identify rpIdHash, flags, counter, and credential public key
- Distinguish "none" vs "packed" attestation and when each is appropriate
- Explain how origin binding in clientDataJSON prevents phishing
- Describe how the authentication ceremony proves possession without revealing the private key

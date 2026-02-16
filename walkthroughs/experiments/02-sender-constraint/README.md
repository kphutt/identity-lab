# Experiment 2: The Sender-Constraint Story — DPoP + DBSC

Learn why bearer tokens are dangerous and how DPoP (RFC 9449) and DBSC bind credentials to the client and device so theft is useless.

## Layer

**Binding** — How are tokens and sessions bound to the client/device so theft is useless? (DPoP, DBSC, sender-constrained tokens)

## What you'll learn

- Why bearer tokens (RFC 6750) are dangerous: possession = access
- How DPoP binds access tokens to a client keypair via the `cnf.jkt` claim
- How to construct and verify a DPoP proof JWT (`dpop+jwt`)
- The difference between `ath` (full SHA-256) and `at_hash` (left-half SHA-256)
- DPoP vs mTLS: when to pick which, and the FAPI 2.0 connection
- How DBSC binds session cookies to the device TPM to defeat infostealers
- The progression: bearer → DPoP-bound → DBSC-bound → nothing is bearer

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

~30 minutes

## After running, you should be able to:

- Explain why a stolen DPoP-bound token is useless without the client's private key
- Draw the DPoP proof structure (header with jwk, payload with htm/htu/ath) and explain each field
- Contrast ath (full SHA-256, 43 chars) with at_hash (left-half, 22 chars) and explain why they differ
- Compare DPoP and mTLS and explain when each is appropriate
- Describe the DBSC flow and why it defeats cookie-stealing infostealers

# Experiment 6: OIDC Discovery + JWKS + Key Rotation

Explore OIDC Discovery, JWKS with multiple keys, kid-based key selection, Cache-Control caching semantics, and the key rotation lifecycle — including what goes wrong when you rotate too fast or too slow.

## Layer

**Identity/Grant** — How does the platform issue and validate identity assertions and access grants? (OIDC, OAuth2, FAPI 2.0, JWKS)

## What you'll learn

- The OIDC Discovery document (`.well-known/openid-configuration`) and every field in it
- JWKS with multiple keys during rotation and kid-based key selection
- Cache-Control max-age semantics and how they affect rotation timing
- The key rotation lifecycle: generate, publish, activate, deactivate, remove
- Normal rotation with overlap windows vs too-fast rotation (self-inflicted outage)
- Compromised key tradeoffs: graceful rotation vs immediate revocation

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

- Explain OIDC Discovery and list the key fields in the discovery document
- Describe kid-based key selection and why multiple keys coexist during rotation
- Calculate the safe overlap window (max-age + token TTL)
- Draw the key rotation lifecycle on a whiteboard
- Argue why compromised keys should be revoked immediately (integrity beats availability)

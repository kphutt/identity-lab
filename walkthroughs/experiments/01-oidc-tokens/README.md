# Experiment 1: OIDC Token Anatomy + Confused Deputy

Construct OIDC ID tokens from scratch, annotate every claim, validate step by step, and break them to learn the confused deputy attack.

## Layer

**Identity/Grant** — How does the platform issue and validate identity assertions and access grants? (OIDC, OAuth2, FAPI 2.0, JWKS)

## What you'll learn

- How JWTs are constructed: header, payload, and signature as three base64url segments
- Every claim in an OIDC ID token and what breaks if it's wrong
- How JWKs and JWKS work for key distribution and signature verification
- The confused deputy attack and why audience validation prevents it
- Token exchange (RFC 8693) as the correct cross-service call pattern

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

- Draw the three parts of a JWT on a whiteboard and explain what each contains
- Explain the confused deputy attack: what it is, what field prevents it, and why token exchange is the fix
- Distinguish sub vs aud, acr vs amr, and explain when each matters

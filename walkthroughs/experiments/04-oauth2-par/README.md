# Experiment 4: OAuth2 Grants + PAR (FAPI 2.0)

Walk through the OAuth2 Authorization Code flow with PKCE, Client Credentials grant, and Pushed Authorization Requests (PAR), culminating in the FAPI 2.0 security profile.

## Layer

**Identity/Grant** — How does the platform issue and validate identity assertions and access grants? (OIDC, OAuth2, FAPI 2.0, JWKS)

## What you'll learn

- The Authorization Code flow end-to-end: authorization request, redirect, token exchange
- Every parameter in the authorization request and token response, annotated
- How PKCE (Proof Key for Code Exchange) prevents authorization code interception
- Client Credentials grant for machine-to-machine flows
- PAR (Pushed Authorization Requests, RFC 9126) and why FAPI 2.0 requires it
- FAPI 2.0 mandatory requirements: PKCE + PAR + sender-constrained tokens + strict redirect_uri

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

- Draw the Authorization Code + PKCE flow on a whiteboard
- Explain how PKCE prevents the code interception attack (SHA-256, one-way hash)
- Distinguish state (CSRF) vs nonce (replay) and when each is checked
- Explain what PAR is and why FAPI 2.0 mandates it
- List the FAPI 2.0 mandatory requirements and what threat each addresses

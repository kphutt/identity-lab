# Experiment 8: CAEP / Shared Signals Framework

Construct and verify real Security Event Tokens (SETs) using jose — the payoff for Experiment 7's revocation timing gap. See how CAEP pushes real-time security events (session revoked, credential compromised, claims changed) to close the JWT revocation gap from minutes to milliseconds.

## Layer

**Enforcement** — How does the system respond to real-time risk changes? (CAEP, Shared Signals Framework)

## What you'll learn

- SET (Security Event Token, RFC 8417) structure — header (typ: secevent+jwt, alg, kid) and payload (iss, iat, jti, aud, events)
- SSF key terms: transmitter, receiver, stream
- HTTP push delivery with Content-Type: application/secevent+jwt
- 6-step receiver verification: signature, issuer, jti dedup, event URI, subject, action
- Session-revoked SET triggered by SCIM DELETE (Experiment 7)
- Credential-change SET for compromised passkeys with iss_sub subject format
- Token-claims-change SET showing stale access token vs current claims
- The JWT revocation gap: minutes without CAEP, milliseconds with it
- Static TTL vs signal-based lifetime comparison

## How to run

```bash
npm install
node run.js
```

Interactive mode steps through one screen at a time. Press ENTER to advance.

For a full dump (all scenarios, no pausing):

```bash
node run.js --no-pause
```

## Estimated time

~25 minutes

## After running, you should be able to:

- Explain what a SET is and how it differs from an access token (typ, key fields, purpose)
- Describe SSF transmitters, receivers, and streams
- Walk through the 6 steps a receiver takes to verify and act on a SET
- Explain how CAEP closes the JWT revocation gap from minutes to milliseconds
- Explain why ALL sessions must be revoked for a compromised credential
- Describe how token-claims-change events solve the embedded claims freshness problem
- Compare static TTL vs signal-based lifetimes (tradeoffs, failure modes, infrastructure)
- Map Layer 4 (Lifecycle) triggers to Layer 5 (Enforcement) events

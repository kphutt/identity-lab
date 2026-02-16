# Walkthroughs — Interactive Protocol Simulations

Step through each protocol as the RP making security decisions.

Each experiment simulates both sides of a protocol, prints narrated output one step at a time, and lets you explore failure modes, attack scenarios, and configuration tradeoffs at interactive exploration points.

## What It Looks Like

```
  STEP 5: Token Validation Lab

  You have a valid token for Service A. Let's see what happens
  when different validation checks fail — or get skipped.

  ❓ Pick a scenario to explore:

    [1]   Skip audience check
    [2]   Accept an expired token
    [3]   Verify with the wrong key
    [4]   Forward token to another service
    [5]   → Continue (all checks passing)

                                                    ▸ pick 1-5 ◂

  ── [1] Skip Audience Check ──

  Token aud:  "https://api.serviceA.com"
  You are:    "https://api.serviceB.com"

  Signature ✓  Expiry ✓  Issuer ✓  Audience... not checked.

  Result: ACCEPTED ⚠️

  This is the confused deputy attack. Service A obtained a valid
  token for its own audience, then forwarded it to you. Without
  audience validation, you can't distinguish "user authenticated
  with me" from "another service relaying someone else's token."

  🎯 INTERVIEW ALERT: "What's the confused deputy problem?"
     A middle service forwards a token to a downstream service.
     Without aud checking, the downstream accepts it. The fix is
     audience validation + token exchange for cross-service calls.
```

## Experiments

| # | Name | Layer | What You'll Learn |
|---|------|-------|-------------------|
| 1 | OIDC Token Anatomy + Confused Deputy | Identity/Grant | JWT construction, every OIDC claim, confused deputy attack, token validation |
| 2 | The Sender-Constraint Story — DPoP + DBSC | Binding | Bearer token theft, DPoP proof construction, DBSC session binding, infostealer defense |
| 3 | WebAuthn Ceremonies | Presence | authenticatorData bytes, flags bitmap, attestation, counter validation |
| 4 | OAuth2 Grants + PAR (FAPI 2.0) | Identity/Grant | Auth Code + PKCE, PAR flow, FAPI 2.0 security profile |
| 5 | Passkeys — Sync vs Device-Bound | Presence | Synced vs hardware-bound, attestation formats, enterprise credential policy |
| 6 | OIDC Discovery + JWKS + Key Rotation | Identity/Grant | JWKS endpoints, key selection, rotation timing, compromise response |
| 7 | SCIM Provisioning + Deprovisioning | Lifecycle | SCIM PATCH format, PUT vs PATCH, deprovisioning cascade |
| 8 | CAEP / Shared Signals | Enforcement | Security Event Tokens, revocation timing gap, signal-based lifetimes |
| 9 | Workload Identity Federation | Cross-cutting | GCP WIF, SPIFFE, Secret Zero anti-pattern |

**Recommended learning path:** Experiments 1-4 cover 80% of the core identity stack.

## How to Run

```bash
cd experiments/01-oidc-tokens
npm install
node run.js
```

Step through with ENTER. Pick scenarios at exploration menus. Use `--no-pause` to dump all output at once (for re-reading or screenshots).

## Requirements

Node.js 18+. Nothing else.

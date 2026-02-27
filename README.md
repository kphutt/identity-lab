# identity-lab

[![Node.js 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Learn the modern identity stack by building it. Nine interactive CLI simulations — step through each protocol as the relying party, making security decisions and triggering failure modes.

## The Problem

Identity specs are fragmented across dozens of RFCs. Tutorials teach the happy path — they don't show what breaks when you skip audience validation, accept an unsigned token, or cache a revoked key. Reading specs tells you what to implement; simulation lets you trigger the failure modes and see why each check exists.

## The Stack

The modern identity stack has five layers. Each layer enforces a distinct security property, and each walkthrough demonstrates one or more:

```
┌─────────────────────────────────────────────┐
│  5. Enforcement — CAEP, Shared Signals      │  Real-time revocation
├─────────────────────────────────────────────┤
│  4. Lifecycle — SCIM provisioning           │  Timely deprovisioning
├─────────────────────────────────────────────┤
│  3. Binding — DPoP, sender constraints      │  Replay prevention
├─────────────────────────────────────────────┤
│  2. Grant — OIDC, OAuth2, FAPI 2.0, JWKS   │  Scoped authority
├─────────────────────────────────────────────┤
│  1. Presence — WebAuthn, passkeys, FIDO2    │  Phishing resistance
└─────────────────────────────────────────────┘
```

## Protocol Invariants

Each invariant is demonstrated by a specific walkthrough that lets you trigger the violation and observe the consequence.

| Invariant | Demonstrated by | Mechanism |
|-----------|----------------|-----------|
| Authority must not exceed granted scope | [04-oauth2-par](walkthroughs/experiments/04-oauth2-par/) | PAR prevents scope tampering; audience validation prevents confused deputy |
| Binding must constrain replay | [02-sender-constraint](walkthroughs/experiments/02-sender-constraint/) | DPoP proof binds token to method, URL, and key |
| Presence must be cryptographically verified | [03-webauthn](walkthroughs/experiments/03-webauthn/) | Origin binding in clientDataJSON prevents phishing |
| Key rotation must maintain integrity | [06-jwks-rotation](walkthroughs/experiments/06-jwks-rotation/) | Overlapping keys during rotation; kid-based selection |
| Lifecycle events must cascade | [07-scim](walkthroughs/experiments/07-scim/) | DELETE triggers disable → revoke → SET event → downstream kill |
| Revocation must happen in real time | [08-caep](walkthroughs/experiments/08-caep/) | SETs close the JWT revocation gap from minutes to milliseconds |
| Workloads must authenticate without static secrets | [09-workload-identity](walkthroughs/experiments/09-workload-identity/) | Platform-attested OIDC tokens with auto-rotation |

## Walkthroughs

| # | Experiment | Layer |
|---|-----------|-------|
| 1 | [OIDC Tokens](walkthroughs/experiments/01-oidc-tokens/) — JWT verification, audience validation, confused deputy | Grant |
| 2 | [Sender Constraint](walkthroughs/experiments/02-sender-constraint/) — DPoP, DBSC, bearer vs bound tokens | Binding |
| 3 | [WebAuthn](walkthroughs/experiments/03-webauthn/) — Registration and authentication ceremonies | Presence |
| 4 | [OAuth2 + PAR](walkthroughs/experiments/04-oauth2-par/) — Authorization code, PKCE, pushed authorization | Grant |
| 5 | [Passkeys](walkthroughs/experiments/05-passkeys/) — Discoverable credentials, backup flags, synced vs device-bound | Presence |
| 6 | [JWKS Rotation](walkthroughs/experiments/06-jwks-rotation/) — Key lifecycle, cache semantics, kid selection | Grant |
| 7 | [SCIM](walkthroughs/experiments/07-scim/) — User provisioning, deprovisioning, DELETE cascade | Lifecycle |
| 8 | [CAEP](walkthroughs/experiments/08-caep/) — Security Event Tokens, real-time revocation | Enforcement |
| 9 | [Workload Identity](walkthroughs/experiments/09-workload-identity/) — Platform-attested tokens, token exchange | Cross-cutting |

## Design Tradeoffs

CLI simulation vs full stack realism. These walkthroughs simulate protocol flows without a browser, network, or external services. The cost: doesn't exercise real HTTP flows or browser behavior. The benefit: isolates the protocol decisions from infrastructure noise — you can focus on *why* each check exists, not how to configure nginx.

## Quick Start

```bash
git clone https://github.com/kphutt/identity-lab.git
cd identity-lab/walkthroughs/experiments/01-oidc-tokens
npm install
node run.js
```

Step through with ENTER. Explore failure modes and attack scenarios at each exploration point. Use `node run.js --no-pause` to dump all output at once.

## Requirements

- Node.js 18+
- Nothing else. No browser, no external services, no credentials.

## References

| Spec | What it covers |
|------|---------------|
| [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | Passkey registration and authentication ceremonies |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 Authorization Framework |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP — Demonstrating Proof of Possession |
| [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) | SCIM Protocol |
| [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | OIDC ID Tokens, claims, flows |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html) | PAR, sender-constrained tokens, strict security |

## License

MIT

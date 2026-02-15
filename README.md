# identity-lab

Learn the modern identity stack by building it.

## Projects

| Project | Description | Status |
|---------|-------------|--------|
| [walkthroughs/](walkthroughs/) | Interactive CLI protocol simulations — step through each protocol as the RP making security decisions | In Progress |

## The Stack

The modern identity stack has five layers. Every project in this repo teaches one or more:

1. **Presence** — WebAuthn, passkeys, FIDO2 attestation
2. **Identity/Grant** — OIDC, OAuth2, FAPI 2.0, JWKS key management
3. **Binding** — DPoP, DBSC, sender-constrained tokens
4. **Lifecycle** — SCIM provisioning and deprovisioning
5. **Enforcement** — CAEP, Shared Signals, real-time revocation

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/identity-lab.git
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

# identity-lab

A collection of hands-on projects for learning the modern identity protocol stack.

## Projects

| Project | Description | Status |
|---------|-------------|--------|
| `walkthroughs/` | Interactive CLI protocol simulations | In Progress |

More projects are planned — real implementation examples (working WebAuthn RP, OAuth2 authorization server, etc.) will sit as peer directories.

## The 5-Layer Stack Model

Every project in this repo maps to layers of the modern identity stack:

1. **Presence** — How does the system know a human is present, and WHICH human? (WebAuthn, passkeys, FIDO2, attestation)
2. **Identity/Grant** — How does the platform issue and validate identity assertions and access grants? (OIDC, OAuth2, FAPI 2.0, JWKS)
3. **Binding** — How are tokens and sessions bound to the client/device so theft is useless? (DPoP, DBSC, sender-constrained tokens)
4. **Lifecycle** — How are identities created, updated, and destroyed? (SCIM, provisioning, deprovisioning)
5. **Enforcement** — How does the system respond to real-time risk changes? (CAEP, Shared Signals Framework)

Organizing principle: *"Sender-constrained tokens to prevent replay, WebAuthn to prevent phishing, CAEP to solve revocation."*

## Tech Stack

- Node.js 18+ (enforced in `.nvmrc`)
- `jose` for JWT construction and verification
- `@simplewebauthn/server` for WebAuthn verification (alongside raw parsing)
- `cbor-x` or `cbor` for CBOR encoding/decoding
- Node `crypto` for key generation, signing, hashing
- No database, no persistence, no external services, no Express

## Walkthroughs — Design & Experiment Specs

For the walkthroughs project's educational principles, formatting rules, and full experiment specifications, see **[walkthroughs/DESIGN.md](walkthroughs/DESIGN.md)**.

When "start experiment N" is invoked, read `walkthroughs/DESIGN.md` for the complete spec.

## File Structure

```
identity-lab/
├── CLAUDE.md                              ← You are here
├── .claude/
│   └── context.md                         ← Personal learning context (gitignored)
├── README.md                              ← Public-facing repo overview
├── LICENSE                                ← MIT
├── .nvmrc                                 ← Node 18
├── .gitignore
│
├── walkthroughs/                          ← Interactive protocol simulations
│   ├── DESIGN.md                          ← Principles, formatting, experiment specs
│   ├── README.md                          ← Project-specific README
│   ├── shared/                            ← Reusable helpers (pause, explore, etc.)
│   ├── experiments/                       ← One directory per experiment
│   └── notes/                             ← Personal observations (gitignored)
│
└── [future peer projects]
```

## Rules

- No root-level `package.json`. Each experiment has its own inside `walkthroughs/experiments/`.
- `walkthroughs/shared/` starts empty. Inline helpers in Experiment 1, refactor to shared/ from Experiment 2.
- Experiment directories start empty (`.gitkeep`). Code is added with "start experiment N".
- `walkthroughs/notes/` is gitignored.

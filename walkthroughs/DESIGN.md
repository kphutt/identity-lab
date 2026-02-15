# Walkthroughs — Design Document

This document defines the educational principles, formatting rules, and experiment specifications for the walkthroughs project. When "start experiment N" is invoked, this is the reference.

---

## What This Project Is

Interactive CLI experiments that simulate both sides of a protocol in pure Node.js (mock authenticator + mock RP, mock client + mock auth server, etc.). The learner steps through one screen at a time, explores failure modes and attack scenarios at exploration points, and builds protocol fluency through direct interaction.

Key terms used throughout:
- **IdP** (Identity Provider, also called OP — OpenID Provider) — the service that authenticates users and issues tokens.
- **RP** (Relying Party) — the service that accepts tokens and makes authorization decisions based on them.
- **AS** (Authorization Server) — issues OAuth2 access tokens. Often the same server as the IdP.

The code is a vehicle. The real deliverable is the interactive experience — it reads like a protocol textbook you play through.

---

## Educational Principles

These are non-negotiable. Every experiment must follow all of them.

### Principle 1: Interactive step-through with exploration points

The default mode is INTERACTIVE. The experiment prints one step at a time and waits for ENTER before continuing. At key protocol moments, the learner hits an **exploration point** — a menu of scenarios they can explore in any order. Each scenario teaches a different behavior (failure mode, configuration choice, attack vector, or design tradeoff), then returns to the menu. The menu tracks visited scenarios with ✓ checkmarks. When the learner has explored enough, they pick "Continue" to advance.

This is NOT right-vs-wrong testing. It's a lab — "what happens if I skip this check? what does this failure look like?" Every branch is educational. The learner builds intuition by seeing multiple outcomes, not by being told which one is correct.

**State machine model:**
```
STEP (linear) → STEP (linear) → EXPLORATION POINT → STEP (linear) → ...
                                   ├── Scenario A (explore, return to menu)
                                   ├── Scenario B (explore, return to menu)
                                   ├── Scenario C (explore, return to menu)
                                   └── Continue → next step
```

Each exploration point should have 3-5 scenarios. The "Continue" option is always last and always available — you don't have to explore every branch, but the checkmarks show what you haven't seen. Revisiting a checked scenario is allowed (it replays).

Implementation:
- `pause()` — waits for ENTER (narrative steps)
- `explore(prompt, scenarios)` — presents numbered menu with ✓ tracking, runs chosen scenario, returns to menu. Each scenario is a function. "Continue" breaks the loop.
- `--no-pause` flag shows ALL scenarios sequentially (all branches, clearly labeled) for re-reading/screenshots.

These helpers are ~30-40 lines total. Inline in Experiment 1, refactor to `shared/` for Experiment 2+.

Every step still: says what's about to happen, shows the data with field-level annotations, explains what each field means and what breaks if it's wrong.

### Principle 2: No browser required

`node run.js`. Mock both sides. No Express, no HTTP server, no UI, no external services, no credentials.

Exception: when mocking HTTP-based protocols (OAuth2 flows, SCIM), simulate HTTP conceptually — print the request object and response object as narrated JSON, don't actually open ports.

### Principle 3: Interview callouts

3-5 🎯 INTERVIEW ALERT per experiment. Each MUST include the specific question AND a concise answer (2-3 sentences). Not topic flags.

### Principle 4: Comparison runs (via exploration or automatic)

Two approaches depending on context:

**Exploration menu (preferred):** When different configurations produce different behavior, make each configuration a scenario in an exploration point. The learner picks "UV required," sees the flags byte, comes back, picks "UV discouraged," sees the diff. Organic comparison through exploration.

**Automatic side-by-side:** For cases where the diff only makes sense when seen together (e.g., byte-level field differences), print both and the diff after the learner has explored the individual scenarios:

```
  ── Comparison: UV required vs UV discouraged ──

  flags byte:   0x45 (UP=1, UV=1, AT=1)  →  0x41 (UP=1, UV=0, AT=1)
  UV bit:       SET                       →  CLEAR
  Why:          UV=required forces biometric/PIN check.
                UV=discouraged allows presence-only (touch).
```

### Principle 5: Summary card as self-test

End every experiment with a ╔══╗ bordered card containing: key structures covered, 3-5 interview Q&A pairs. The card header must say: "Cover the answers below. Try to answer each from memory." Frame it as active recall, not a reference sheet.

### Principle 6: Exploration points

Each experiment should have 1-3 exploration points — menus where the learner picks scenarios to explore. Each scenario is educational, not a pass/fail test. Design scenarios around:

- **Failure modes:** "What happens if you skip X?" — show the attack or error
- **Configuration choices:** "What changes if you set UV to required vs discouraged?" — show the concrete difference
- **Architecture tradeoffs:** "DPoP or mTLS? Bearer or sender-constrained?" — show what each gives you and what it costs
- **Attack vectors:** "What can an attacker do with a stolen token/cookie/key?" — show the blast radius

Every scenario should end with a concrete takeaway — not "that was wrong" but "here's what you'd see in production and here's what it means for your design."

The menu loop ensures all scenarios get covered even if the learner starts with the "obvious" one. Checkmarks make uncovered ground visible.

Every exploration point's "Continue" option must show concrete content — a summary comparison, a flow diagram, or the happy-path walkthrough. "Continue" should never just advance to the next step with nothing new.

### Principle 7: Practice prompt

After the summary card, end with a ⏸ PRACTICE block. One specific articulation exercise: "Close this terminal. Explain out loud [specific concept]. Then come back and check." The exercise should target the most likely interview question for that experiment.

### Principle 8: Inspectability

When using libraries, ALSO show the raw bytes/JSON before the library processes them.

### Principle 9: Output length

Target 100-150 lines of narrated output (not counting pause prompts). If it needs more, accept optional flags for extra content (e.g., `node run.js --failures`). The default run should never exceed ~150 lines of content.

### Principle 10: Every data structure gets the ID token treatment

When the experiment shows a JSON object, JWT, byte sequence, HTTP request, or HTTP response, annotate EVERY field using the `↳` pattern from the canonical example:

```
"field": "value",
    ↳ Full Name. WHAT IT IS in plain English.
      What the RP/client/server does with it. What breaks if it's wrong.
```

No unannotated fields. If it appears in the output, it gets an explanation. This applies to: JWT headers, JWT payloads, JWKs, JWKS, DPoP proofs, authenticatorData bytes, clientDataJSON, attestationObject, SCIM resources, SCIM PATCH operations, Security Event Tokens, OAuth2 request/response parameters, .well-known/openid-configuration fields, COSE keys, and any other structured data.

### Principle 11: Terminology on first use, reminders on reuse

Every acronym, protocol name, and technical term must be expanded and explained on first use within an experiment. Not just the expansion — what it IS, what it DOES, and why the learner should care. The learner should be able to say the term confidently in an interview after seeing it once.

When a term from a previous experiment reappears in a later experiment, include a one-line parenthetical reminder on first reuse. Example: "aud (audience — who the token is for, from Experiment 1)". The learner should never need to go back to a previous experiment to remember what a term means.

---

## Canonical Output Example

Every experiment must match this formatting style. This shows the step-through flow, exploration point with menu, field annotations, interview alerts, summary card, and practice prompt:

```
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 1: OIDC Token Anatomy + Confused Deputy             ║
║  Layer: Identity/Grant                                          ║
║  Time: ~25 minutes                                              ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.         ║
╚══════════════════════════════════════════════════════════════════╝

This experiment constructs OIDC tokens from scratch, walks through
every claim, validates them step by step, and then breaks them.

                                                ▸ press ENTER ◂
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  STEP 1: Generating the Signing Key

  Generating an EC P-256 keypair...

  Private key (JWK):
  {
    "kty": "EC",
    "crv": "P-256",
    "x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d":   "jpsQnnGQmL-YBIffS1BSyVKhrlRiZvG9GkXkpKVnSJA",
    "kid": "key-2026-02-15"
  }

  The "d" parameter is the private key — never leaves the
  authorization server. The public key (x, y) goes in the JWKS.

                                                ▸ press ENTER ◂
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  STEP 2: Constructing the ID Token — Payload (Claims)

  {
    "iss": "https://idp.example.com",
        ↳ Issuer. Who created this token. The RP checks this
          matches the IdP it trusts.

    "sub": "user-8492",
        ↳ Subject. WHO THE USER IS. Stable, unique at this IdP.
          Not an email — emails get reassigned.

    "aud": "https://api.serviceA.com",
        ↳ Audience. WHO THIS TOKEN IS FOR. The intended recipient.
          Service A checks: "is aud ME?" If not, REJECT.
          This prevents the confused deputy attack.

    🎯 INTERVIEW ALERT: "What's the difference between sub and aud?"
       sub = the user's identity (WHO is authenticated)
       aud = the token's intended recipient (WHO should accept it)
       Confusing them is the confused deputy vulnerability.

    "acr": "urn:mace:incommon:iap:silver",
        ↳ Authentication Context Class Reference. The assurance level
          the IdP claims for this login. RP uses it for policy.

    "amr": ["hwk", "face"],
        ↳ Authentication Methods References. HOW the user actually
          authenticated. "hwk" = hardware key, "face" = biometric.

    🎯 INTERVIEW ALERT: "What's the difference between acr and amr?"
       acr = assurance level (policy classification)
       amr = specific methods used (audit trail)
       RP requests minimum acr; IdP returns what it achieved + amr.
  }

                                                ▸ press ENTER ◂
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

  The fix: always check aud matches YOUR service identifier.
  Cross-service calls use token exchange (RFC 8693) to get a
  new token with the correct audience.

  🎯 INTERVIEW ALERT: "What's the confused deputy problem?"
     A middle service forwards a token to a downstream service.
     Without aud checking, the downstream accepts it. The fix is
     audience validation + token exchange for cross-service calls.

                                                ▸ press ENTER ◂

  ❓ Pick a scenario to explore:

    [1] ✓ Skip audience check
    [2]   Accept an expired token
    [3]   Verify with the wrong key
    [4]   Forward token to another service
    [5]   → Continue (all checks passing)

                                                    ▸ pick 1-5 ◂

  ── [2] Accept an Expired Token ──

  Token exp: 1739635200 (1 hour ago)
  Current:   1739638800

  Signature ✓  Issuer ✓  Audience ✓  Expiry... 3600 seconds past.

  Result: REJECTED ✅

  Even with a valid signature and correct audience, expired tokens
  MUST be rejected. Short-lived tokens limit the blast radius of
  theft. If you accept expired tokens, a stolen token is useful
  forever.

  🎯 INTERVIEW ALERT: "Why not just use long-lived tokens?"
     Shorter TTL = smaller theft window. The tradeoff: too short =
     constant re-auth. CAEP (Experiment 8) closes the gap — revoke
     in real time instead of waiting for expiry.

                                                ▸ press ENTER ◂

                                                ▸ press ENTER ◂
╔══════════════════════════════════════════════════════════════════╗
║  SUMMARY CARD                                                    ║
║  Cover the answers below. Try to answer each from memory.        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Key structures: JWT header, payload claims, JWKS, JWK           ║
║                                                                  ║
║  Q: What's the difference between sub and aud?                   ║
║  A: sub = who the user is. aud = who the token is for.           ║
║                                                                  ║
║  Q: What's the confused deputy problem?                          ║
║  A: Service A forwards its token to B. Without aud checking,     ║
║     B accepts it. Token exchange (RFC 8693) is the fix.          ║
║                                                                  ║
║  Q: acr vs amr?                                                  ║
║  A: acr = assurance level (policy). amr = methods used (audit).  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

⏸  PRACTICE: Close this terminal. Explain out loud what the
   confused deputy attack is, what field prevents it, and why
   token exchange is the right pattern. Then come back and check.
```

---

## Formatting Rules

- `━━━` line separators between steps
- `╔══╗` box for title block and summary card only
- `↳` for field annotations, indented 8 spaces under the field
- `🎯 INTERVIEW ALERT:` inline in the flow, not in separate boxes
- `❓ Pick a scenario to explore:` for exploration menus
- `[N] ✓` for visited scenarios, `[N]` (no checkmark) for unvisited
- `→ Continue` as last option in every exploration menu
- `── [N] Scenario Name ──` for scenario headers within exploration
- `✓` and `✗` for validation pass/fail within scenarios
- `✅` for expected/correct outcomes, `⚠️` for dangerous outcomes (not "wrong answers" — educational labels)
- `▸ press ENTER ◂` after narrative steps, `▸ pick N ◂` for exploration menus
- `⏸ PRACTICE:` at the very end, one specific articulation exercise
- No ANSI colors (must work piped to a file)
- 2-space indent for all content within a step
- Blank line between each annotated field for readability

---

## Tech Stack

- Node.js 18+ (enforced in `.nvmrc`)
- `jose` for JWT construction and verification
- `@simplewebauthn/server` for WebAuthn verification (alongside raw parsing)
- `cbor-x` or `cbor` for CBOR encoding/decoding
- Node `crypto` for key generation, signing, hashing
- No database, no persistence, no external services, no Express

---

## Experiment Roadmap

Experiments are numbered in **priority order**. The learner does them 1, 2, 3... and stops when time runs out. Highest-value experiments first.

### The 5-Layer Stack

1. **Presence** — WebAuthn, passkeys, attestation
2. **Identity/Grant** — OIDC, OAuth2, FAPI 2.0, JWKS
3. **Binding** — DPoP, DBSC, sender-constrained tokens
4. **Lifecycle** — SCIM, provisioning
5. **Enforcement** — CAEP, Shared Signals

---

### Experiment 1: OIDC Token Anatomy + Confused Deputy
**Layer:** Identity/Grant

OIDC (OpenID Connect) is an identity layer built on top of OAuth2. OAuth2 gives you an access token (authorization); OIDC adds an ID token that tells you WHO the user is (authentication).

Construct JWTs (JSON Web Tokens, pronounced "jot") from scratch — a signed JSON payload encoded as three base64url segments: header.payload.signature. The signature proves it hasn't been tampered with.

Generate an EC P-256 keypair (Elliptic Curve, NIST P-256 — the standard signing algorithm for OIDC, also called "ES256" in JWT headers). Build a JWKS (JSON Web Key Set — a JSON document containing an array of public keys, published at a well-known URL so RPs can fetch them for signature verification).

**JWT header — annotate every field:**
- `alg` (Algorithm) — "ES256" means ECDSA with P-256 and SHA-256. Tells the verifier which algorithm to use.
- `typ` (Type) — "JWT" for ID tokens, "at+jwt" for access tokens (per RFC 9068). Resource servers use this to reject ID tokens presented as access tokens.
- `kid` (Key ID) — identifies WHICH key in the JWKS was used to sign this token. The verifier fetches the JWKS, finds the key matching this kid, and uses it for verification.

**JWK (JSON Web Key) fields — annotate every field:**

A JWK is a standard JSON format for representing a cryptographic key. This is what goes in the JWKS endpoint.

- `kty` (Key Type) — "EC" for Elliptic Curve.
- `crv` (Curve) — "P-256" for the NIST P-256 curve.
- `x`, `y` — the public key coordinates (base64url-encoded). These go in the JWKS.
- `d` — the private key. NEVER leaves the authorization server. Never in the JWKS.
- `kid` (Key ID) — matches the kid in JWT headers to select this key.
- `use` (Public Key Use) — "sig" for signing.
- `alg` (Algorithm) — "ES256" to restrict this key to one algorithm.

**ID token payload — annotate EVERY claim using `↳` pattern:**
- `iss` — Issuer. Who created this token. RP checks this matches the IdP it trusts.
- `sub` — Subject. WHO THE USER IS. Stable, unique at this IdP. Not an email — emails get reassigned. Federated account linking uses iss+sub, never email.
- `aud` — Audience. WHO THIS TOKEN IS FOR. The intended recipient. RP checks: "is aud ME?" If not, REJECT. Prevents confused deputy.
- `azp` — Authorized Party. WHO REQUESTED this token. When aud has multiple values, azp identifies the specific client. If aud is a single value and matches azp, azp is optional.
- `nonce` — a random value the client sends in the auth request and expects back in the ID token. Prevents replay attacks. Different from PKCE: nonce protects the ID token, PKCE protects the auth code.
- `at_hash` — Access Token Hash. Left half of SHA-256 hash of the access token, base64url-encoded. Binds the ID token to its companion access token so they can't be mixed.
- `c_hash` — Code Hash. Same as at_hash but for the authorization code. Binds the ID token to the code in the hybrid flow.
- `auth_time` — Unix timestamp of when the user actually authenticated. RP checks this to enforce max_age: "don't accept logins older than X seconds."
- `exp` — Expiration Time. Unix timestamp. After this moment, REJECT unconditionally. Short TTLs limit blast radius of token theft.
- `iat` — Issued At. When this token was created. Used for freshness checks and audit.
- `acr` — Authentication Context Class Reference. The assurance level the IdP claims for this login. RP uses it for step-up auth policy.
- `amr` — Authentication Methods References. HOW the user actually authenticated ("hwk" = hardware key, "face" = biometric, "pwd" = password, etc.).

Critical distinctions to give significant space:
- sub vs aud — sub is the user, aud is the intended recipient. Confusing them is confused deputy.
- aud vs azp — aud is who the token is FOR, azp is who REQUESTED it.
- acr vs amr — acr is assurance level (policy), amr is methods actually used (audit).

Validation walkthrough — every check in order, narrated. Then an exploration point:

Exploration point — "Token Validation Lab":
- **Skip audience check** → confused deputy attack. Token meant for Service A accepted by Service B. Show the attack, explain the fix (aud validation + token exchange).
- **Accept an expired token** → expired 1 hour ago, sig still valid. Show rejection. Explain: short TTLs limit blast radius; CAEP (Continuous Access Evaluation Protocol, Experiment 8) closes the gap for real-time revocation.
- **Verify with wrong key** → kid mismatch or different keypair. Show signature failure. Explain: this is what happens during botched key rotation (see Experiment 6).
- **Accept token from untrusted issuer** → iss doesn't match the RP's trusted issuer list. Show rejection. Explain: issuer validation defines your trust boundary. Accepting tokens from unknown issuers means anyone can assert identity to your service.
- **Continue (all checks passing)** → show the full validation chain succeeding, every check annotated. Then show the token exchange (RFC 8693) flow as the correct cross-service call pattern: client sends subject_token + audience parameter to the STS (Security Token Service — the server that performs token exchanges), gets back a new token with the correct aud. Show the exchange request and response with `↳` annotations for: grant_type (urn:ietf:params:oauth:grant-type:token-exchange), subject_token, subject_token_type, audience, and the response with the new access_token.

Summary card should include: sub vs aud, confused deputy + fix, acr vs amr, token exchange as the correct cross-service pattern, iss+sub for account linking (never email).

---

### Experiment 2: The Sender-Constraint Story — DPoP + DBSC
**Layer:** Binding

Through-line: "Nothing should be a bearer credential."

A bearer token (per RFC 6750) is a token that grants access to whoever holds it, no questions asked. Like a house key: anyone who has it can use it. The name comes from "the bearer of this token." This is the fundamental problem this experiment addresses.

**Part 1 — The bearer problem + DPoP fix:**

DPoP (Demonstrating Proof of Possession, RFC 9449) — the client generates a keypair, includes the public key in token requests, and proves possession of the private key on every API call. A stolen token is useless without the client's key.

Exploration point — "Stolen Token Lab":
- **Replay bearer token from different client** → it works. The resource server has no way to know the token was stolen. Explain the fundamental bearer problem: possession = access.
- **Replay DPoP-bound token without the proof** → rejected. Attacker has the access token but can't produce a valid DPoP proof without the client's private key. The resource server requires the DPoP header and rejects without it.
- **Replay DPoP-bound token with proof for wrong endpoint** → rejected. Proof has htm=GET htu=/data, but attacker tries POST /admin. The htm/htu binding catches the mismatch.
- **Replay DPoP-bound token with proof using a different access token** → rejected. The ath (access token hash) in the proof doesn't match the presented token. The proof is bound to the specific token it was issued with.
- **Continue** → show a summary: "DPoP binds the token to: the client's key (proof), the endpoint (htm/htu), the moment (iat), and the specific token (ath). An attacker needs ALL of these to replay." Then transition to DBSC.

**Part 2 — DPoP proof construction:** Build the DPoP proof JWT with `↳` annotations for every field.

DPoP proof header:
- `typ` — "dpop+jwt". Identifies this as a DPoP proof, not a regular JWT.
- `alg` — the signing algorithm (e.g., "ES256").
- `jwk` — the client's PUBLIC key, embedded in the header. The resource server uses this to verify the proof signature. On first use, the AS binds this key to the access token via the cnf claim.

DPoP proof payload:
- `jti` (JWT ID) — a unique identifier for this specific proof. The server rejects any jti it has seen before (replay prevention).
- `htm` (HTTP Method) — "GET", "POST", etc. The proof is bound to this method. Wrong method = rejected.
- `htu` (HTTP Target URI) — the full URL of the resource. The proof is bound to this endpoint. Wrong endpoint = rejected.
- `iat` (Issued At) — timestamp. Servers enforce a time window (typically seconds to minutes). Old proofs are rejected.
- `ath` (Access Token Hash) — SHA-256 of the access token, base64url-encoded. Binds this proof to this specific token. **CRITICAL: ath is ONLY in resource requests, NOT token requests** (at the token endpoint, you don't have a token yet).
- `nonce` — (optional) a server-provided value the client must echo. The server sends it in a `DPoP-Nonce` response header. Prevents pre-generated proofs.

Also show the access token's `cnf` (confirmation) claim:
- `cnf.jkt` (JWK Thumbprint) — a hash of the client's public key, embedded in the access token by the AS. The resource server computes the thumbprint from the proof's jwk header and checks it matches cnf.jkt. This is how the binding is verified: the token says "I belong to key X" and the proof proves "I have key X."

DPoP vs mTLS (mutual TLS — both client and server present certificates during TLS handshake) comparison:
- DPoP: application layer, works through proxies/CDNs, per-request, key in WebCrypto (the browser's built-in crypto API — non-exportable keys mean even XSS can't extract them, though the attacker can use them while the page is compromised)
- mTLS: transport layer, breaks at proxy/CDN termination (they terminate TLS, severing the client cert binding), per-connection, key in cert store
- Pick: DPoP for public clients (browsers, mobile apps), mTLS for backend-to-backend

FAPI 2.0 (Financial-grade API — see Experiment 4): sender-constrained tokens are MANDATORY.

**Part 3 — DBSC (Device Bound Session Credentials):** The gap: even with DPoP, the session cookie is still a bearer credential. An infostealer (malware that extracts cookies and tokens from the browser's storage — the standard way MFA gets bypassed in practice: attacker steals the session cookie AFTER the user has already authenticated) grabs the cookie → full session hijack.

DBSC binds session cookies to the device's TPM (Trusted Platform Module — a hardware security chip that can generate and store keys; the private key never leaves the chip).

DBSC flow — walk through each step with narrated request/response:
1. User logs in successfully (MFA, WebAuthn, whatever)
2. Browser calls the DBSC API → generates a keypair in the TPM
3. Browser sends the public key to the server in a registration request
4. Server stores the public key, associates it with the session, issues a session cookie
5. On session refresh: server sends a challenge in the response
6. Browser signs the challenge with the TPM private key
7. Server verifies signature against stored public key → session refreshed
8. Attack scenario: stolen cookie on a different machine → attacker can't sign the challenge (no TPM private key) → session refresh fails → cookie is useless

Note: DBSC can't be simulated with real TPM in Node. Mock the keypair generation and signature flow. Narrate what the TPM does. The protocol flow is real; the hardware binding is narrated. This is fine — the interview asks about the architecture, not TPM APIs.

Per-site key scoping (each site gets its own keypair — prevents cross-site tracking). Status: W3C draft, Chrome implementation.

**Part 4 — Connected:** Bearer → DPoP-bound → DBSC-bound → nothing is bearer.

---

### Experiment 3: WebAuthn Ceremonies — Registration + Authentication
**Layer:** Presence

WebAuthn (Web Authentication API) — a W3C standard that lets websites use public-key cryptography instead of passwords. The browser mediates between the website (RP) and the authenticator (USB key, platform biometric, phone). Defined in WebAuthn Level 3.

Mock authenticator + mock RP.

**Registration:**

Show the PublicKeyCredentialCreationOptions with `↳` annotations:
- `rp` — the Relying Party: `{id: "example.com", name: "Example Corp"}`. The rpId is typically the domain. Credentials are bound to this rpId.
- `user` — the user: `{id: <random bytes>, name: "alice@example.com", displayName: "Alice"}`. The user.id is opaque bytes, NOT the username.
- `challenge` — random bytes from the RP. The authenticator signs over this to prove freshness. Must be at least 16 bytes, used once.
- `pubKeyCredParams` — which algorithms the RP accepts: `[{type: "public-key", alg: -7}]`. -7 = ES256 (ECDSA P-256).
- `authenticatorSelection` — RP's requirements: `{authenticatorAttachment, residentKey, userVerification}`.
- `attestation` — "none", "direct", or "indirect". How much the RP wants to know about the authenticator.

authenticatorData — a binary blob the authenticator produces. Annotate byte-by-byte using `↳`:
- rpIdHash (bytes 0-31) — SHA-256 hash of the RP ID (e.g., "example.com"). The RP checks this matches its own identity. This binds the credential to this domain — a credential registered at bank.com cannot be used at evil.com.
- flags (byte 32) — a single byte, each bit matters:
  - Bit 0: UP (User Present) — someone physically touched the authenticator.
  - Bit 2: UV (User Verified) — biometric or PIN confirmed WHO the user is, not just that someone is there.
  - Bit 6: AT (Attested Credential Data) — new credential data is included (set during registration, not authentication).
  - Bit 7: ED (Extension Data) — extensions are present.
- counter (bytes 33-36) — a monotonically increasing number (big-endian uint32). The RP stores the last-seen counter. If the next authentication has a LOWER counter, the credential may have been cloned. This is the ONLY cloned-credential detection mechanism in WebAuthn.
- AAGUID (bytes 37-52) — Authenticator Attestation GUID. A 128-bit identifier for the authenticator MODEL (not individual device). All YubiKey 5 NFC devices share the same AAGUID. Look this up in the FIDO MDS (Metadata Service — a database run by the FIDO Alliance containing metadata for every certified authenticator: name, capabilities, certification level, known vulnerabilities) to learn about the authenticator's properties.
- credentialIdLength (bytes 53-54) — big-endian uint16, length of the credential ID that follows.
- credentialId — the identifier for this credential. The RP stores this for future authentication.
- COSE public key — the credential's public key in COSE (CBOR Object Signing and Encryption) format. CBOR (Concise Binary Object Representation) is a binary encoding format like JSON but compact and binary. WebAuthn uses it for attestation objects and COSE keys. Annotate the COSE key fields: kty (2 = EC2), alg (-7 = ES256), crv (1 = P-256), x and y coordinates. Map COSE integer codes to their human-readable meanings.

clientDataJSON — a JSON object the BROWSER constructs (not the authenticator). Annotate every field:
- `type` — "webauthn.create" for registration, "webauthn.get" for authentication.
- `challenge` — base64url encoding of the RP's challenge bytes.
- `origin` — the website URL (e.g., "https://bank.com"). THIS IS THE PHISHING DEFENSE. The browser sets this to the actual page URL. A phishing site at evil.com produces origin=evil.com. The RP checks this against its expected origin.
- `crossOrigin` — boolean, whether the request came from a cross-origin iframe.

attestationObject — a CBOR-encoded structure containing the authenticator's proof of identity. Show the raw CBOR hex alongside parsed:
- `fmt` (format) — attestation format string. "none" = authenticator doesn't prove what it is (privacy-preserving). "packed" = standard attestation with optional certificate chain.
- `attStmt` (attestation statement) — varies by format. For "packed" with x5c: includes the certificate chain. For "none": empty object.
  - `x5c` — the attestation certificate chain in X.509 DER format. First cert is the authenticator's attestation cert; rest chain to a root CA. Verify against FIDO MDS root certificates to trust the attestation.
- `authData` — the authenticatorData bytes described above.

Comparison run: attestation "none" vs "packed" with x5c.

**Authentication:** Re-register first (self-contained). Walk through signature verification step by step:
1. Compute SHA-256 hash of the clientDataJSON bytes
2. Concatenate: authenticatorData || hash(clientDataJSON) — this byte order is CRITICAL
3. Verify the signature over that concatenation using the stored public key
4. Check counter > stored counter (clone detection)
Show the actual bytes being concatenated.

Exploration point — "RP Configuration Lab":
- **UV required** → run the ceremony, show flags byte with UV bit SET (e.g., 0x45). Explain: RP knows the user proved their identity with biometric/PIN. Use this for sensitive operations.
- **UV discouraged** → run the ceremony, show flags byte with UV bit CLEAR (e.g., 0x41). Explain: RP only knows someone touched the authenticator, not WHO. Fine for low-risk re-authentication.
- **Attestation "packed" with x5c** → show the attestation statement with certificate chain. Show AAGUID. Explain: RP can verify authenticator model via FIDO MDS lookup. Enterprise use case.
- **Attestation "none"** → show the empty attestation. Show AAGUID is still present but unverified. Explain: RP learns nothing verified about the authenticator. Privacy-preserving, good for consumer sites.
- **Cloned authenticator (counter rollback)** → show counter going from 5 to 3. Explain: RP should flag or reject. The counter is the only cloned-key detection mechanism. Some authenticators (especially synced passkeys) always return 0 — in that case, counter checking is useless.
- **Continue** → show the comparison summary of UV required vs discouraged (flags byte diff side by side), plus attestation none vs packed (what the RP knows in each case).

Interview alerts:
- CTAP2: "Browser talks to authenticator via CTAP2 (CBOR over USB/NFC/BLE). Browser handles origin binding, authenticator handles key gen + user verification. Authenticator never sees origin; browser never sees private key."
- Biometrics: "Authenticator matches biometric locally. The RP only sees the UV bit (yes/no). No biometric data ever leaves the authenticator."
- **Phishing: "How does WebAuthn prevent phishing?" The BROWSER sets the origin field in clientDataJSON to the actual page URL. A phishing site at evil.com produces origin=evil.com. The RP checks this against its expected origin. Additionally, the credential is bound to the rpId (the domain). The authenticator won't use a credential registered at bank.com when asked by evil.com. Neither the user nor the attacker can override these bindings.**

---

### Experiment 4: OAuth2 Grants + PAR (FAPI 2.0)
**Layer:** Identity/Grant

OAuth 2.0 (RFC 6749) — an authorization framework. The user grants a client limited access to their resources without sharing their password. Produces access tokens. OIDC (OpenID Connect, from Experiment 1) adds identity on top.

Mock client + mock authorization server. Every HTTP request/response as narrated JSON with `↳` annotations.

**Authorization Code flow** — the most secure OAuth2 flow:
1. User visits AS → authenticates → AS redirects back with a short-lived authorization code
2. Client exchanges code for tokens server-to-server
3. The tokens never touch the browser

Show the authorization request with `↳` annotations for every parameter:
- `response_type` — "code" for Authorization Code flow.
- `client_id` — identifies the client application.
- `redirect_uri` — the URL the AS sends the user back to. MUST be pre-registered and EXACTLY matched. Open redirectors (loose matching) are a classic OAuth vulnerability that lets attackers steal auth codes.
- `scope` — what access the client is requesting (e.g., "openid profile email").
- `state` — a random value the client generates and expects back unchanged. Prevents CSRF attacks on the redirect endpoint. Client checks: "did I generate this state value?"
- `nonce` — (when requesting OIDC ID tokens) random value bound to the ID token. Different from PKCE: nonce protects the ID token from replay, PKCE protects the auth code from interception.

**PKCE (Proof Key for Code Exchange, pronounced "pixie", RFC 7636)** — show the full mechanism step by step:
1. Client generates a `code_verifier` — a random string, 43-128 characters, from the unreserved character set
2. Client computes `code_challenge` = base64url(SHA-256(code_verifier))
3. Client sends the `code_challenge` and `code_challenge_method` ("S256") in the authorization request — this is a HASH of the secret, not the secret itself
4. AS stores the challenge, issues the authorization code
5. Client sends the `code_verifier` (the ORIGINAL SECRET) in the token exchange request
6. AS re-computes: base64url(SHA-256(received_verifier)) and compares to stored challenge
7. If they match → tokens issued. If not → rejected.

WHY this works: An attacker who intercepts the authorization code (e.g., malicious app registered to the same URL scheme, browser extension, network observer) only saw the `code_challenge` in step 3 — that's the HASH. SHA-256 is one-way: knowing the hash doesn't give you the verifier. Without the verifier, the attacker can't complete step 5.

S256 = SHA-256 as the code_challenge_method. The alternative is "plain" (no hashing), which provides no security. Always use S256. Mandatory in OAuth 2.1.

Show the token request with `↳` annotations:
- `grant_type` — "authorization_code"
- `code` — the authorization code from the redirect
- `redirect_uri` — must match the original request exactly
- `client_id` — the client
- `code_verifier` — the original PKCE secret

Show the token response with `↳` annotations:
- `access_token` — the token for API calls
- `token_type` — "DPoP" if sender-constrained (Experiment 2), "Bearer" otherwise
- `expires_in` — seconds until expiration
- `id_token` — the OIDC identity token (Experiment 1)
- `refresh_token` — long-lived token to get new access tokens without re-authentication

**Client Credentials grant** — machine-to-machine flow, no user involved. The client authenticates directly with its own credentials (client_id + client_secret, or private_key_jwt) and gets an access token. Used for service-to-service calls.

**PAR (Pushed Authorization Requests, RFC 9126)** — instead of putting all authorization parameters in the browser URL (where the user can see and tamper with them), the client POSTs them directly to the AS server-to-server. The AS returns an opaque request_uri. The browser redirect contains only this request_uri — no PII, no tamperable params.

Exploration point — "Authorization Flow Lab":
- **Baseline OAuth2 (params in URL)** → show the full authorization URL with ALL params visible in the browser address bar: response_type, client_id, redirect_uri, scope, state, code_challenge, login_hint. Annotate each. Explain: the user can see PII (login_hint, scope), an attacker on the network can see them, and the params are tamperable. URL length limits can be a problem for complex requests.
- **PAR (server-to-server push)** → show the PAR POST request body (all the same params, plus client authentication) sent directly to the AS. Show the response with `↳` annotations: `request_uri` (an opaque reference the AS returns — the client puts ONLY this in the browser redirect, the AS looks up original params by this reference) and `expires_in` (how long the request_uri is valid). Show the resulting authorization URL with only client_id and request_uri visible. Explain: params are authenticated (AS verified the client), PII hidden from browser, AS can reject bad requests early.
- **No PKCE** → show the authorization code interception attack step by step: (1) legitimate client starts auth flow, (2) malicious app registers the same custom URL scheme (e.g., myapp://), (3) AS redirects with ?code=abc123 in the URL, (4) BOTH apps receive the redirect, malicious app grabs the code, (5) malicious app sends the code to the token endpoint — it WORKS because there's no proof the legitimate client started the flow. Show the actual redirect URL with the code visible.
- **With PKCE** → same interception scenario, but the malicious app doesn't have the code_verifier. Show: malicious app sends the intercepted code to token endpoint → AS checks code_verifier → no verifier provided or wrong verifier → REJECTED. The legitimate client sends the same code with its code_verifier → AS re-hashes → matches the stored challenge → tokens issued.
- **Continue** → FAPI 2.0 (Financial-grade API — a security profile on top of OAuth2/OIDC designed for high-value use cases: banking, healthcare, government) summary with each requirement annotated:
  - PKCE required (prevents code interception — explained above)
  - PAR required (prevents parameter tampering, hides PII)
  - Sender-constrained tokens required — DPoP or mTLS (prevents token theft — Experiment 2)
  - Strict redirect_uri matching (prevents open redirect attacks)
  - No implicit flow (tokens must never appear in URL fragments)
  - JARM optional — JWT Secured Authorization Response Mode. The AS signs its authorization response as a JWT, so the response parameters (including the authorization code and state) can't be tampered with by an attacker. The client verifies the JWT signature before extracting the code.

FAPI 2.0 = "PKCE + PAR + sender-constrained tokens + strict redirect URI."

---

### Experiment 5: Passkeys — Sync vs Device-Bound + Attestation
**Layer:** Presence

A passkey is the industry term for a WebAuthn discoverable credential (residentKey: "required"). The credential is stored ON the authenticator so it can be discovered without the RP providing a credential ID list. This enables "sign in with your passkey" without typing a username.

Key concepts with `↳` annotations:
- `residentKey` — the RP's preference for discoverable credentials. "required" = must be discoverable (passkey UX, no allowCredentials needed). "discouraged" = server-side credential storage, RP must provide allowCredentials list during authentication. "preferred" = discoverable if the authenticator supports it.
- `allowCredentials` — a list of credential IDs the RP sends during authentication: "which of these credentials do you have?" For non-discoverable credentials, this is required. For passkeys (discoverable), this list is empty — the authenticator finds the credential itself.
- `authenticatorAttachment` — "platform" means built into the device (TouchID, Windows Hello, phone biometric). "cross-platform" means a separate device (USB security key, NFC card, phone-as-authenticator via hybrid transport).
- Hybrid transport (formerly caBLE) — use your phone as a cross-platform authenticator for a laptop. A QR code or Bluetooth proximity establishes the connection. This is how "use your phone" passkey prompts work.
- Conditional UI — the browser shows passkey suggestions in the username field's autofill dropdown, without a full WebAuthn modal. Triggered by `navigator.credentials.get({mediation: "conditional"})`. The user sees their passkey alongside saved passwords. Requires discoverable credentials.

Syncable passkey: private key syncs via cloud (iCloud Keychain, Google Password Manager, 1Password). Attestation is typically "none" — the cloud provider doesn't attest on behalf of the original authenticator. Consumer-friendly: easy recovery if device is lost.

Device-bound credential: private key stays on a specific piece of hardware. "packed" attestation with x5c (certificate chain — from Experiment 3) provides hardware assurance. The RP can verify the authenticator model via AAGUID (authenticator model identifier — from Experiment 3) lookup in the FIDO MDS.

Exploration point — "Credential Registration Policy Lab":
- **Synced passkey (iCloud Keychain)** → run registration, show attestation "none", show empty attStmt. Show the AAGUID (present but unverified without attestation). Explain: great UX, easy recovery, but the private key lives in the cloud provider's security perimeter. Trust chain now includes Apple/Google's cloud security. RP learns nothing verified about the authenticator.
- **Hardware security key (YubiKey)** → run registration, show "packed" attestation with x5c chain, show AAGUID. Look up AAGUID → "YubiKey 5 NFC, FIDO2 L1 certified." Explain: private key provably in hardware, can't be exported, RP knows the exact model and its certification level.
- **Platform authenticator (TouchID/Windows Hello)** → run registration, show authenticatorAttachment "platform", typically "none" attestation. Explain: device-bound (key doesn't sync) but not portable. User loses the device, loses the credential. Account recovery strategy is essential. This is why sites let you register multiple credentials.
- **Phone as authenticator (hybrid transport)** → narrate the cross-device flow: laptop shows QR code → phone scans it → Bluetooth proximity check → phone's platform authenticator handles the ceremony → response tunneled back to laptop. Explain: the credential lives on the phone, but the authentication happens on the laptop. The phone is a "cross-platform" authenticator from the laptop's perspective.
- **Continue** → comparison summary: what the RP can determine from each type. Table showing: attestation format, AAGUID usable?, hardware assurance, key exportable?, recovery story. Then enterprise policy guidance: device-bound for admin/privileged accounts (require hardware attestation — if the cloud account is compromised, a synced passkey is too), synced for general workforce (balance security with UX), and how to enforce via attestation format + AAGUID allowlisting.

---

### Experiment 6: OIDC Discovery + JWKS + Key Rotation
**Layer:** Identity/Grant

**.well-known/openid-configuration** — the OIDC Discovery document. A JSON file at `https://issuer/.well-known/openid-configuration`. The RP fetches this ONCE and knows everything about the IdP. Annotate every key field:
- `issuer` — the IdP's canonical URL. Must EXACTLY match the `iss` claim (from Experiment 1) in tokens.
- `authorization_endpoint` — where to send the user to authenticate.
- `token_endpoint` — where the client exchanges codes for tokens (server-to-server).
- `jwks_uri` — the URL of the JWKS (the public keys for signature verification).
- `scopes_supported` — which scopes the IdP supports ("openid", "profile", "email", etc.).
- `response_types_supported` — which OAuth2 flows ("code", "id_token", etc.).
- `id_token_signing_alg_values_supported` — which algorithms for ID tokens (e.g., ["ES256", "RS256"]).
- `token_endpoint_auth_methods_supported` — how clients authenticate at the token endpoint ("client_secret_basic", "client_secret_post", "private_key_jwt").

**JWKS** with multiple keys, selection by kid (Key ID — identifies which key signed a token, from Experiment 1).

The JWKS endpoint returns `Cache-Control: max-age=N` headers. RPs cache the JWKS for N seconds before re-fetching. During key rotation, the overlap window MUST be longer than max-age, or RPs with stale caches will reject valid tokens signed with the new key.

Exploration point — "Key Rotation Scenarios":
- **Normal rotation (overlap window)** → Show timeline: Day 0: JWKS = [Key A], sign with A. Day 1: JWKS = [Key A, Key B], sign new tokens with B, old A tokens still verify. Day 3 (after max-age expires): JWKS = [Key B only], remove A. Show: tokens signed with A still validate during overlap (RPs have A in cache). After removal + cache expiry, old A tokens fail gracefully (they've likely expired by then). This is the safe path. The overlap window must be at least max-age + token TTL.
- **Rotation too fast (remove key early)** → remove Key A before max-age elapses. Show: an RP with stale cache tries to verify a token signed with B → kid not found in cached JWKS → smart RP re-fetches JWKS, finds B, succeeds. But: a token signed with A after removal → kid found in stale cache but key removed from source → on re-fetch, gone → REJECTED. Explain: this is an outage you caused.
- **Compromised key — graceful rotation** → keep compromised Key A in JWKS during overlap. Show: attacker has the private key for A → forges tokens → tokens validate because A is still in JWKS. Show a timeline: compromise detected at hour 0, overlap window is 24 hours, attacker can forge valid tokens for 24 hours. Explain the tradeoff explicitly.
- **Compromised key — immediate revocation** → remove Key A from JWKS NOW. Show: legitimate tokens signed with A → REJECTED (users must re-authenticate). Forged tokens also fail immediately. Explain: integrity beats availability. A temporary outage (users re-auth) is better than knowingly accepting forged tokens for hours.
- **Continue** → key lifecycle timeline diagram: `generate → publish (overlap) → activate (sign new) → deactivate (stop signing) → remove (after max-age + TTL)`. Show Cache-Control max-age relationship explicitly. Summary: "Normal: overlap > max-age + TTL. Compromise: revoke immediately, accept re-auth cost."

Summary card: "Integrity beats availability. Compromised key = remove from JWKS immediately, force re-auth. Graceful rotation with a compromised key means knowingly accepting forged tokens."

---

### Experiment 7: SCIM Provisioning + Deprovisioning
**Layer:** Lifecycle

SCIM (System for Cross-domain Identity Management, RFC 7644) — a REST API for provisioning and deprovisioning user accounts across systems. The IdP (or HR system) pushes user lifecycle events (create, update, disable, delete) to downstream services.

**POST /Users** — create a user. Show the full resource with `↳` annotations:
- `schemas` — `["urn:ietf:params:scim:schemas:core:2.0:User"]`. Schema URIs identify the resource type. Extensions add their own URIs to this array.
- `userName` — the unique identifier (often an email or employee ID).
- `name` — `{givenName, familyName, formatted}`.
- `emails` — array of `{value, type, primary}`. Multiple emails with types like "work", "home".
- `active` — boolean. false = disabled but not deleted. This is the soft-delete mechanism.
- `groups` — the user's group memberships (often read-only, managed via Group resources).

**PATCH** — show the Operations array with `↳` annotations:
```
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      ↳ The schema URI for PATCH operations. Required.
  "Operations": [
      ↳ An array of operations to apply, in order.
    {
      "op": "replace",
          ↳ Operation type. "add" (create or append), "remove" (delete),
            or "replace" (overwrite). These are the only three.
      "path": "active",
          ↳ Which attribute to modify. Dot notation for nested
            fields: "name.givenName". Can target array elements
            with filters: "emails[type eq \"work\"].value".
      "value": false
          ↳ The new value. For "replace", overwrites the field.
            For "add", creates the field or appends to arrays.
    },
    {
      "op": "add",
      "path": "emails",
      "value": [{"value": "new@example.com", "type": "work"}]
          ↳ Adds to the emails array without replacing existing entries.
    }
  ]
}
```

Exploration point — "Lifecycle Operations Lab":
- **PATCH (surgical update)** → show the PATCH request changing active=false and adding an email. Show the before and after resource side by side. Only the specified fields changed, everything else preserved. Explain: PATCH is the safe update method for partial modifications.
- **PUT (full replace)** → show a PUT request that includes name and active but OMITS the emails field. Show before: user has 2 emails. Show after: user has 0 emails — the emails field is GONE. Emails were DELETED because PUT replaces the ENTIRE resource; any field not in the PUT body is removed. Explain: this is why PATCH is safer. Never use PUT for partial updates. PUT means "this is the complete new state of this resource."
- **DELETE with proper cascade** → DELETE /Users/123. Show the cascade step by step: (1) set active=false, (2) revoke all active sessions at downstream services, (3) emit a CAEP (Continuous Access Evaluation Protocol — real-time revocation signals, covered fully in Experiment 8) session-revoked event, (4) downstream resource servers receive the event and kill sessions within seconds. Show the SET event. Explain: deprovisioning must be fast. A terminated employee's access should be gone in seconds, not minutes.
- **DELETE without CAEP** → same DELETE, but no CAEP event. Show: user is disabled in the IdP. But the user's existing sessions at downstream services (with valid JWTs from Experiment 1) continue working. With a 10-minute token TTL, that's up to 10 minutes of access after termination. Show the timeline: minute 0 → DELETE → minute 3 → API call → ACCEPTED (token still valid) → minute 10 → token expires → REJECTED. Explain: this is the revocation timing gap CAEP closes.
- **Continue** → SCIM vs JIT comparison. SCIM (push provisioning): IdP pushes create/update/delete to services independently of login. Full lifecycle control. JIT (Just-In-Time provisioning): user account created on first login using OIDC token claims (from Experiment 1) — no pre-provisioning needed. Tradeoff: SCIM handles the full lifecycle (pre-provision before first login, update attributes, deprovisioning) while JIT only creates on first auth and has no deprovisioning mechanism. Show a comparison table: provisioning timing, attribute updates, deprovisioning, complexity.

Summary card: full identity lifecycle — IAL (Identity Assurance Level, NIST 800-63: IAL1 = self-asserted, IAL2 = remote identity proofing with photo ID + selfie, IAL3 = in-person verification with a trained operator) verification → WebAuthn registration (Experiment 3) → SCIM/JIT provisioning → authentication → session binding with DBSC (Experiment 2) → API access with DPoP (Experiment 2) → deprovisioning (SCIM DELETE + CAEP Experiment 8).

---

### Experiment 8: CAEP / Shared Signals Framework
**Layer:** Enforcement

CAEP (Continuous Access Evaluation Protocol) is part of the SSF (Shared Signals Framework — the umbrella spec that defines how transmitters publish events and receivers consume them). Services publish real-time security events so other services can react immediately. This solves the JWT revocation gap: self-contained tokens (from Experiment 1) can't be revoked until they expire, but CAEP signals tell the resource server to drop the session NOW.

Key terms:
- **Transmitter** — the service that detects a security event and sends it. Example: IdP detects password reset.
- **Receiver** — the service that acts on the event. Example: resource server revokes sessions.
- **Stream** — a configured delivery channel between a transmitter and receiver. The receiver subscribes to event types it cares about.

**SET (Security Event Token, RFC 8417)** — a JWT that carries a security event. Not an access grant — an event notification. Show the full structure with `↳` annotations:

SET header:
- `typ` — "secevent+jwt". Identifies this as a Security Event Token, not a regular JWT or access token.
- `alg` — signing algorithm (e.g., "ES256").
- `kid` — key ID for signature verification (same JWKS pattern as Experiment 1).

SET payload:
- `iss` — the transmitter's identifier (who detected and sent the event).
- `iat` — when the SET was generated (may differ from when the event occurred).
- `jti` — unique event ID. Receivers track seen jti values for deduplication.
- `aud` — the receiver's identifier (who should process this event).
- `events` — the event data. A JSON object keyed by event-type URIs, each containing event-specific fields:
```
"events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
        ↳ Event type URI. Globally unique identifier for this kind of event.
          The URI is the key; the value object contains event details.
        "subject": {
            "format": "opaque",
            "id": "session-id-abc123"
            ↳ The subject of the event — which session to revoke.
              Format can be "opaque", "email", "iss_sub", etc.
        },
        "event_timestamp": 1739638800,
            ↳ When the event actually occurred (may be before iat if
              there was a detection/delivery delay).
        "reason_admin": {
            "en": "User terminated"
            ↳ Human-readable reason. For audit logs and admin UIs.
        }
    }
}
```

HTTP push delivery: the transmitter POSTs the SET to the receiver's configured endpoint. The receiver verifies the SET signature against the transmitter's JWKS before acting on it.

Exploration point — "Security Event Lab":
- **Session revoked (deprovisioning)** → construct a session-revoked SET triggered by SCIM DELETE (from Experiment 7). Show the full JWT with every field annotated. Walk through the receiver's verification: (1) verify SET signature against transmitter's JWKS, (2) check iss is a trusted transmitter, (3) check jti for deduplication, (4) extract event type URI, (5) find the session by subject.id, (6) kill it immediately regardless of token expiry. Explain: the session is dead within seconds of the SCIM DELETE.
- **Credential compromised** → construct a credential-change SET. Show: event data includes which credential was affected. Receiver action: revoke ALL sessions that were established using that credential. Explain: this is the response to a stolen passkey or leaked signing key. Even if the sessions are otherwise valid, the authentication that created them is no longer trustworthy.
- **Token claims changed (role change)** → construct a token-claims-change SET. Show: user's group membership changed mid-session (e.g., removed from "admins" group). The access token (from Experiment 1) still says groups=["admins"] but the SET says that's stale. Receiver must re-evaluate authorization — either force a token refresh or revoke the session. Explain: this is why tokens with embedded claims have a freshness problem.
- **No CAEP (static TTL only)** → show the revocation timing gap with concrete math. Token TTL = 10 minutes. User deprovisioned at minute 2. Timeline: minute 2 → SCIM DELETE → IdP disables user → minute 3 → API call with valid token → ACCEPTED (still valid for 7 more minutes) → minute 5 → API call → ACCEPTED → minute 10 → token expires → finally REJECTED. That's 8 minutes of unauthorized access. Then show the same timeline with CAEP: minute 2 → SCIM DELETE → CAEP session-revoked event sent → receiver kills session at minute 2.001 → minute 3 → API call → REJECTED. Gap reduced from 8 minutes to milliseconds.
- **Continue** → signal-based lifetimes vs static TTLs summary. Static: pick a TTL and accept the gap (shorter TTL = smaller gap but more re-auth load on the IdP). Signal-based: use CAEP events to revoke on demand; token TTL becomes a performance optimization (how long to cache the authorization decision) rather than a security boundary. Show the tradeoff: static TTL is simpler (no event infrastructure) but has a revocation gap; CAEP eliminates the gap but requires transmitter/receiver infrastructure and stream management.

Connection map (narrate after exploration): SCIM DELETE → triggers session-revoked SET. Credential compromise detected → triggers credential-change SET. Role change in directory → triggers token-claims-change SET. Show how layers 4 (Lifecycle) and 5 (Enforcement) work together.

---

### Experiment 9 (optional): Workload Identity Federation
**Layer:** Cross-cutting

Only build this if experiments 1-8 are done.

WIF (Workload Identity Federation) — lets workloads (pods, VMs, CI jobs) authenticate to cloud services using their native identity tokens instead of static secrets. The cloud trusts the workload's OIDC token (same JWT format from Experiment 1) after verifying it against the workload's IdP.

- GCP WIF flow: K8s pod gets an OIDC token from the cluster's IdP → presents it to GCP's STS (Security Token Service — exchanges one token for another, same pattern as RFC 8693 token exchange from Experiment 1) → STS verifies the token against the cluster's JWKS (from Experiment 6) → STS issues a short-lived GCP access token. No static keys anywhere.
- SPIFFE (Secure Production Identity Framework for Everyone) — a standard for workload identity. Defines the SPIFFE ID format: `spiffe://trust-domain/workload-path`. SVID (SPIFFE Verifiable Identity Document) — an X.509 cert or JWT proving the workload's identity.
- Secret Zero anti-pattern: "I need a secret to get my secrets." If you use a static API key to access your secret manager, you've just moved the problem — now you need to protect that API key. WIF solves this: the workload's identity IS its credential, derived from the platform (Kubernetes service account token, VM instance metadata), not from a stored secret.

---

## Experiment Directory Convention

When "start experiment N" is invoked, generate:

- `walkthroughs/experiments/NN-name/run.js` — single entry point, all output logic
- `walkthroughs/experiments/NN-name/package.json` — name, version, dependencies
- `walkthroughs/experiments/NN-name/README.md` — structured as:
  - Title + one-line description
  - Layer (which of the 5 stack layers)
  - What you'll learn (3-5 bullet points)
  - How to run: `npm install && node run.js` (and `node run.js --no-pause` for full dump)
  - Optional flags (if any)
  - Estimated time: ~X minutes
  - **After running, you should be able to:** (2-3 specific things the learner can now explain on a whiteboard. These are self-check criteria.)

The experiment must work immediately: `cd walkthroughs/experiments/01-oidc-tokens && npm install && node run.js`

After verification, commit. Then anyone can clone and run.

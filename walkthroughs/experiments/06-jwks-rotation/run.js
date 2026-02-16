#!/usr/bin/env node

// Experiment 6: OIDC Discovery + JWKS + Key Rotation
// Layer: Identity/Grant
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import * as jose from 'jose';
import { randomBytes } from 'node:crypto';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Key Generation ──────────────────────────────────────────
  // Key A — current signing key (will be rotated out)
  const { publicKey: publicKeyA, privateKey: privateKeyA } =
    await jose.generateKeyPair('ES256');
  const publicJwkA = await jose.exportJWK(publicKeyA);
  const kidA = 'key-A-2025-01-01';
  publicJwkA.kid = kidA;
  publicJwkA.use = 'sig';
  publicJwkA.alg = 'ES256';

  // Key B — new signing key (rotation target)
  const { publicKey: publicKeyB, privateKey: privateKeyB } =
    await jose.generateKeyPair('ES256');
  const publicJwkB = await jose.exportJWK(publicKeyB);
  const kidB = 'key-B-2025-02-01';
  publicJwkB.kid = kidB;
  publicJwkB.use = 'sig';
  publicJwkB.alg = 'ES256';

  // ── Pre-built Artifacts ─────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  const maxAge = 3600;    // Cache-Control max-age (1 hour)
  const tokenTTL = 3600;  // Token lifetime (1 hour)

  // OIDC Discovery document
  const discoveryDoc = {
    issuer: 'https://auth.example.com',
    authorization_endpoint: 'https://auth.example.com/authorize',
    token_endpoint: 'https://auth.example.com/oauth/token',
    jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    id_token_signing_alg_values_supported: ['ES256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt', 'client_secret_post'],
    subject_types_supported: ['public'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'email', 'name'],
  };

  // JWKS variants for rotation scenarios
  const jwksKeyAOnly = { keys: [publicJwkA] };
  const jwksBothKeys = { keys: [publicJwkA, publicJwkB] };
  const jwksKeyBOnly = { keys: [publicJwkB] };

  // Token signed with Key A
  const tokenSignedA = await new jose.SignJWT({
    iss: 'https://auth.example.com',
    sub: 'user-7291',
    aud: 'client-app-abc',
    nonce: randomBytes(16).toString('base64url'),
    exp: now + tokenTTL,
    iat: now,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: kidA })
    .sign(privateKeyA);

  // Token signed with Key B
  const tokenSignedB = await new jose.SignJWT({
    iss: 'https://auth.example.com',
    sub: 'user-7291',
    aud: 'client-app-abc',
    nonce: randomBytes(16).toString('base64url'),
    exp: now + tokenTTL,
    iat: now,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: kidB })
    .sign(privateKeyB);

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 6: OIDC Discovery + JWKS + Key Rotation             ║
║  Layer: Identity/Grant                                          ║
║  Time: ~20 minutes                                              ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  The JWKS is a live document. Get rotation wrong and you either break
  legitimate sessions or keep accepting forged tokens. This experiment
  covers the operational lifecycle — how keys get published, rotated,
  and revoked, and what goes wrong when you do it too fast or too slow.

  Builds on: Experiment 1 (JWK, JWKS, kid, JWT structure)
             Experiment 4 (token_endpoint, client auth, signed tokens)
`);
  await pause();

  // ── STEP 1: OIDC Discovery Document ────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: OIDC Discovery Document

  Every OIDC provider publishes a JSON document at a well-known URL:
  https://auth.example.com/.well-known/openid-configuration

  An RP (Relying Party) fetches this once and learns everything about
  the Identity Provider — endpoints, supported algorithms, where to
  get the public keys. No hardcoded URLs needed.

  GET https://auth.example.com/.well-known/openid-configuration

  {
    "issuer": "${discoveryDoc.issuer}",
        ↳ Issuer Identifier. The canonical URL of the IdP. This MUST
          exactly match the "iss" claim in every token the IdP issues
          (cross-ref: Experiment 1, Step 4 — iss claim validation).
          Mismatch = reject the token.

    "authorization_endpoint": "${discoveryDoc.authorization_endpoint}",
        ↳ Authorization Endpoint. Where the RP redirects users to
          authenticate (cross-ref: Experiment 4 — authorization request).

    "token_endpoint": "${discoveryDoc.token_endpoint}",
        ↳ Token Endpoint. Where the RP exchanges the authorization code
          for tokens, server-to-server (cross-ref: Experiment 4, Step 4
          — token request).

    "jwks_uri": "${discoveryDoc.jwks_uri}",
        ↳ JWKS URI. The URL where the IdP publishes its public signing
          keys. The RP fetches this to verify token signatures
          (cross-ref: Experiment 1, Step 2 — JWKS). This is the key
          URL for rotation — when keys change, this document changes.

    "scopes_supported": ${JSON.stringify(discoveryDoc.scopes_supported)},
        ↳ Supported Scopes. What the RP can request. "openid" is
          mandatory for OIDC (triggers ID token issuance).

    "response_types_supported": ${JSON.stringify(discoveryDoc.response_types_supported)},
        ↳ Supported Response Types. "code" = Authorization Code flow.
          FAPI 2.0 prohibits "token" (implicit flow).

    "id_token_signing_alg_values_supported": ${JSON.stringify(discoveryDoc.id_token_signing_alg_values_supported)},
        ↳ Supported Signing Algorithms. ES256 (ECDSA with P-256 +
          SHA-256). The RP uses this to know which algorithm to expect
          when verifying signatures.

    "token_endpoint_auth_methods_supported": ${JSON.stringify(discoveryDoc.token_endpoint_auth_methods_supported)},
        ↳ Client Auth Methods. How clients authenticate at the token
          endpoint. "private_key_jwt" = client signs a JWT with its own
          key (cross-ref: Experiment 4, Step 6 — client assertion).

    "subject_types_supported": ${JSON.stringify(discoveryDoc.subject_types_supported)},
        ↳ Subject Types. "public" = same sub for all clients.
          "pairwise" = different sub per client (privacy preserving).

    "claims_supported": ${JSON.stringify(discoveryDoc.claims_supported)}
        ↳ Supported Claims. What claims the IdP can include in tokens.
          The RP knows what user data it can request.
  }

  🎯 INTERVIEW ALERT: "What is OIDC Discovery?"
     A JSON document at https://issuer/.well-known/openid-configuration.
     The RP fetches it once and learns everything about the IdP: issuer
     URL, endpoints, supported algorithms, JWKS URI. The issuer field
     must exactly match the "iss" claim in tokens.
`);
  await pause();

  // ── STEP 2: JWKS with Multiple Keys ────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: JWKS with Multiple Keys

  The jwks_uri returns a JWKS — a JSON document containing the IdP's
  public signing keys. During key rotation, multiple keys coexist:

  GET ${discoveryDoc.jwks_uri}
  Cache-Control: public, max-age=${maxAge}

  {
    "keys": [
      {
        "kty": "${publicJwkA.kty}",
            ↳ Key Type. "EC" = Elliptic Curve.

        "crv": "${publicJwkA.crv}",
            ↳ Curve. "P-256" for ES256.

        "x": "${publicJwkA.x}",
        "y": "${publicJwkA.y}",
            ↳ Public key coordinates (base64url). These are the public
              values — safe to publish. The private key ("d") is NEVER
              in the JWKS.

        "kid": "${kidA}",
            ↳ Key ID. Matches the "kid" in JWT headers. Date-based kid
              makes it easy to see which key is newer.
              (cross-ref: Experiment 1 — kid in JWK)

        "use": "sig",
            ↳ Key Use. "sig" = signing. "enc" would be for encryption.

        "alg": "ES256"
            ↳ Algorithm. ES256 = ECDSA with P-256 + SHA-256.
      },
      {
        "kty": "${publicJwkB.kty}",
        "crv": "${publicJwkB.crv}",
        "x": "${publicJwkB.x}",
        "y": "${publicJwkB.y}",
        "kid": "${kidB}",
        "use": "sig",
        "alg": "ES256"
            ↳ Second key — added during rotation. Both keys are valid
              for verification during the overlap window.
      }
    ]
  }

  kid selection: When an RP receives a JWT, it reads the "kid" from
  the JWT header, then searches the JWKS "keys" array for the matching
  kid. This is how the RP knows which key to use for verification.

  Cache-Control: max-age=${maxAge} (${maxAge / 3600} hour). The RP fetches the JWKS and
  caches it for ${maxAge} seconds. During this window, the RP won't see any
  key changes. This is critical for rotation timing.

  🎯 INTERVIEW ALERT: "How does kid-based key selection work?"
     The JWT header contains a "kid" (Key ID). The RP fetches the JWKS
     from jwks_uri, finds the key with the matching kid, and uses it
     to verify the signature. During rotation, multiple keys coexist
     in the JWKS so both old and new tokens verify.
`);
  await pause();

  // ── STEP 3: Signing and Verifying with kid Lookup ──────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Decode token headers for display
  const headerA = jose.decodeProtectedHeader(tokenSignedA);
  const headerB = jose.decodeProtectedHeader(tokenSignedB);

  console.log(`
  STEP 3: Signing and Verifying with kid Lookup

  Token signed with Key A:
  ${tokenSignedA.slice(0, 60)}...

  JWT Header: ${JSON.stringify(headerA)}
    ↳ kid="${kidA}" tells the RP which key to use.

  Verification flow:
  1. Decode JWT header → extract kid "${kidA}"
  2. Search JWKS keys array for kid="${kidA}"
  3. Found → use that key to verify signature`);

  // Verify token A against JWKS with both keys
  const jwksVerifierBoth = jose.createLocalJWKSet(jwksBothKeys);
  try {
    const { payload } = await jose.jwtVerify(tokenSignedA, jwksVerifierBoth, {
      issuer: 'https://auth.example.com',
      audience: 'client-app-abc',
    });
    console.log(`  4. jose.jwtVerify() → ACCEPTED ✅`);
    console.log(`     sub: ${payload.sub}, iss: ${payload.iss}`);
  } catch (err) {
    console.log(`  4. jose.jwtVerify() → REJECTED ✗ (${err.message})`);
  }

  console.log();
  console.log(`  Token signed with Key B:`);
  console.log(`  ${tokenSignedB.slice(0, 60)}...`);
  console.log();
  console.log(`  JWT Header: ${JSON.stringify(headerB)}`);
  console.log(`    ↳ kid="${kidB}" — the new key.`);
  console.log();
  console.log(`  Verification: kid="${kidB}" → find in JWKS → verify`);

  // Verify token B against JWKS with both keys
  try {
    const { payload } = await jose.jwtVerify(tokenSignedB, jwksVerifierBoth, {
      issuer: 'https://auth.example.com',
      audience: 'client-app-abc',
    });
    console.log(`  jose.jwtVerify() → ACCEPTED ✅`);
    console.log(`     sub: ${payload.sub}, iss: ${payload.iss}`);
  } catch (err) {
    console.log(`  jose.jwtVerify() → REJECTED ✗ (${err.message})`);
  }

  console.log();
  console.log(`  What happens when kid doesn't match?`);
  console.log();

  // Try to verify token B against JWKS with only Key A
  const jwksVerifierAOnly = jose.createLocalJWKSet(jwksKeyAOnly);
  try {
    await jose.jwtVerify(tokenSignedB, jwksVerifierAOnly, {
      issuer: 'https://auth.example.com',
      audience: 'client-app-abc',
    });
    console.log(`  token-B against JWKS=[A] → ACCEPTED ⚠️`);
  } catch (err) {
    console.log(`  token-B (kid="${kidB}") against JWKS=[A only]`);
    console.log(`  jose.jwtVerify() → REJECTED ✗`);
    console.log(`  Error: "${err.message}"`);
    console.log(`    ↳ kid "${kidB}" not found in JWKS. The RP has no key to verify with.`);
  }

  console.log(`
  🎯 INTERVIEW ALERT: "What should an RP do when the kid doesn't match?"
     Re-fetch the JWKS from the jwks_uri. The key may have been added
     during rotation. If it's still not found after re-fetch, reject
     the token. Never verify without the correct key.
`);
  await pause();

  // ── STEP 4: Key Rotation Scenarios (Exploration Point) ─────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 4: Key Rotation Scenarios

  Key rotation isn't just "swap the key." The timing matters. Cache-Control,
  token TTL, and the overlap window determine whether rotation is smooth
  or causes an outage.

  Settings: Cache-Control max-age = ${maxAge}s (${maxAge / 3600}h), Token TTL = ${tokenTTL}s (${tokenTTL / 3600}h)`);

  await explore('Pick a rotation scenario to explore:', [
    {
      name: 'Normal rotation (overlap window)',
      fn: async () => {
        console.log(`  Normal Key Rotation — The Safe Way`);
        console.log();
        console.log(`  Timeline:`);
        console.log();
        console.log(`  Day 0 (now):        JWKS = [A]         Sign with: A`);
        console.log(`  Day 1 (add B):      JWKS = [A, B]      Sign with: B`);
        console.log(`  Day 3 (remove A):   JWKS = [B]         Sign with: B`);
        console.log();
        console.log(`  ──────┬──────────┬──────────┬──────────────────────`);
        console.log(`  Day 0 │  Day 1   │  Day 2   │  Day 3`);
        console.log(`  [A]   │  [A,B]   │  [A,B]   │  [B]`);
        console.log(`  sign A│  sign B  │  sign B  │  sign B`);
        console.log(`        │◀── overlap window ──▶│`);
        console.log(`        │  A tokens still      │`);
        console.log(`        │  verify during this   │`);
        console.log(`        │  window               │`);
        console.log(`  ──────┴──────────┴──────────┴──────────────────────`);
        console.log();
        console.log(`  Key rule: overlap window >= max-age + token TTL`);
        console.log(`  = ${maxAge}s + ${tokenTTL}s = ${maxAge + tokenTTL}s (${(maxAge + tokenTTL) / 3600} hours minimum)`);
        console.log();
        console.log(`  Real verification — token-A validates during overlap:`);
        console.log();

        // Token A against JWKS with both keys
        const verifier = jose.createLocalJWKSet(jwksBothKeys);
        try {
          const { payload } = await jose.jwtVerify(tokenSignedA, verifier, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  token-A against JWKS=[A,B] → ACCEPTED ✅`);
          console.log(`    sub: ${payload.sub}`);
        } catch (err) {
          console.log(`  token-A against JWKS=[A,B] → REJECTED ✗ (${err.message})`);
        }

        console.log();

        // Token B against JWKS with B only (after A is removed)
        const verifierB = jose.createLocalJWKSet(jwksKeyBOnly);
        try {
          const { payload } = await jose.jwtVerify(tokenSignedB, verifierB, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  token-B against JWKS=[B] (after A removed) → ACCEPTED ✅`);
          console.log(`    sub: ${payload.sub}`);
        } catch (err) {
          console.log(`  token-B against JWKS=[B] → REJECTED ✗ (${err.message})`);
        }

        console.log();
        console.log(`  Both old and new tokens verify throughout the transition.`);
        console.log(`  No user impact. No re-authentication needed.`);
      },
    },
    {
      name: 'Rotation too fast (remove key early)',
      fn: async () => {
        console.log(`  Rotation Too Fast — Self-Inflicted Outage`);
        console.log();
        console.log(`  What happens when you remove Key A before max-age expires:`);
        console.log();
        console.log(`  Hour 0:   JWKS = [A, B], start signing with B`);
        console.log(`  Hour 0.5: Remove A from JWKS → JWKS = [B]`);
        console.log(`            But: RP cached JWKS at hour 0, cache expires at hour 1`);
        console.log();
        console.log(`  Problem 1: RP with stale cache sees token signed with B`);
        console.log(`    → RP's cached JWKS = [A], kid "${kidB}" not found`);
        console.log(`    → Smart RP re-fetches JWKS → finds [B] → ACCEPTED`);
        console.log();
        console.log(`  Problem 2: Token signed with A, RP re-fetches after removal`);
        console.log(`    → Updated JWKS = [B], kid "${kidA}" not found`);
        console.log();

        // Demonstrate: token-A against JWKS with only B
        const verifierBOnly = jose.createLocalJWKSet(jwksKeyBOnly);
        try {
          await jose.jwtVerify(tokenSignedA, verifierBOnly, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  token-A against JWKS=[B] → ACCEPTED ⚠️`);
        } catch (err) {
          console.log(`  token-A against JWKS=[B] → REJECTED ✗`);
          console.log(`  Error: "${err.message}"`);
        }

        console.log();
        console.log(`  ⚠️  SELF-INFLICTED OUTAGE: Legitimate users with valid tokens`);
        console.log(`  signed by Key A are rejected. They must re-authenticate even`);
        console.log(`  though their tokens haven't expired. You broke your own users.`);
        console.log();
        console.log(`  Fix: Keep A in JWKS for at least max-age (${maxAge}s) + token TTL`);
        console.log(`  (${tokenTTL}s) = ${maxAge + tokenTTL}s after you stop signing with A.`);
      },
    },
    {
      name: 'Compromised key — graceful rotation',
      fn: async () => {
        console.log(`  Compromised Key — Graceful Rotation (Dangerous)`);
        console.log();
        console.log(`  Scenario: Key A's private key is compromised. An attacker has`);
        console.log(`  a copy and can sign tokens that look legitimate.`);
        console.log();
        console.log(`  You decide to rotate gracefully — keep A in the JWKS during`);
        console.log(`  the standard overlap window while transitioning to B.`);
        console.log();
        console.log(`  Timeline:`);
        console.log(`  Hour 0:  Compromise detected. JWKS = [A, B], sign new with B.`);
        console.log(`  Hour 24: Overlap complete. Remove A from JWKS.`);
        console.log();
        console.log(`  During those 24 hours, the attacker signs a forged token with A:`);
        console.log();

        // Simulate attacker signing with compromised Key A
        const forgedToken = await new jose.SignJWT({
          iss: 'https://auth.example.com',
          sub: 'admin-0001',
          aud: 'client-app-abc',
          scope: 'admin:full',
          exp: now + tokenTTL,
          iat: now,
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: kidA })
          .sign(privateKeyA);

        console.log(`  Forged token: ${forgedToken.slice(0, 60)}...`);
        console.log(`    ↳ Signed with compromised Key A, claiming sub: "admin-0001"`);
        console.log(`      and scope: "admin:full"`);
        console.log();

        // Verify forged token — it succeeds because A is still in JWKS
        const verifier = jose.createLocalJWKSet(jwksBothKeys);
        try {
          const { payload } = await jose.jwtVerify(forgedToken, verifier, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  Forged token against JWKS=[A,B] → ACCEPTED ⚠️`);
          console.log(`    sub: ${payload.sub}, scope: ${payload.scope}`);
        } catch (err) {
          console.log(`  Forged token → REJECTED ✗ (${err.message})`);
        }

        console.log();
        console.log(`  ⚠️  The forged token validates because Key A is still in the JWKS.`);
        console.log(`  Graceful rotation with a compromised key = 24 hours of accepting`);
        console.log(`  forged tokens. The attacker can impersonate any user.`);
      },
    },
    {
      name: 'Compromised key — immediate revocation',
      fn: async () => {
        console.log(`  Compromised Key — Immediate Revocation (Correct Response)`);
        console.log();
        console.log(`  Remove Key A from the JWKS immediately. Don't wait for the`);
        console.log(`  overlap window. Yes, this breaks legitimate tokens.`);
        console.log();
        console.log(`  Hour 0: Compromise detected. JWKS = [B] (A removed immediately).`);
        console.log();
        console.log(`  Consequence 1: Legitimate token signed with A`);
        console.log();

        // Legitimate token A against JWKS with only B
        const verifierBOnly = jose.createLocalJWKSet(jwksKeyBOnly);
        try {
          await jose.jwtVerify(tokenSignedA, verifierBOnly, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  Legitimate token-A against JWKS=[B] → ACCEPTED ⚠️`);
        } catch (err) {
          console.log(`  Legitimate token-A against JWKS=[B] → REJECTED ✗`);
          console.log(`  Error: "${err.message}"`);
        }

        console.log(`    ↳ Legitimate users must re-authenticate. This is the cost.`);
        console.log();

        // Forged token also rejected
        const forgedToken = await new jose.SignJWT({
          iss: 'https://auth.example.com',
          sub: 'admin-0001',
          aud: 'client-app-abc',
          scope: 'admin:full',
          exp: now + tokenTTL,
          iat: now,
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: kidA })
          .sign(privateKeyA);

        console.log(`  Consequence 2: Forged token signed with compromised A`);
        console.log();

        try {
          await jose.jwtVerify(forgedToken, verifierBOnly, {
            issuer: 'https://auth.example.com',
            audience: 'client-app-abc',
          });
          console.log(`  Forged token against JWKS=[B] → ACCEPTED ⚠️`);
        } catch (err) {
          console.log(`  Forged token against JWKS=[B] → REJECTED ✅`);
          console.log(`  Error: "${err.message}"`);
        }

        console.log(`    ↳ Attacker's forged tokens are also rejected. Attack stopped.`);
        console.log();
        console.log(`  Integrity beats availability. Users re-authenticating is`);
        console.log(`  inconvenient. Accepting forged tokens is a security breach.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "Should you immediately revoke a compromised`);
        console.log(`     signing key?"`);
        console.log(`     Yes. Remove it from the JWKS immediately. Legitimate tokens`);
        console.log(`     signed with it will be rejected (users re-authenticate), but`);
        console.log(`     this is better than knowingly accepting forged tokens.`);
        console.log(`     Integrity beats availability.`);
      },
    },
    {
      name: 'Continue (lifecycle + comparison)',
      fn: async () => {
        console.log(`  Key Lifecycle`);
        console.log();
        console.log(`  Every signing key moves through these stages:`);
        console.log();
        console.log(`  ┌──────────┐    ┌─────────┐    ┌──────────┐    ┌────────────┐    ┌────────┐`);
        console.log(`  │ Generate │───▶│ Publish │───▶│ Activate │───▶│ Deactivate │───▶│ Remove │`);
        console.log(`  └──────────┘    └─────────┘    └──────────┘    └────────────┘    └────────┘`);
        console.log();
        console.log(`  Generate:    Create new keypair. Key exists only in HSM/KMS.`);
        console.log(`  Publish:     Add public key to JWKS. Not yet used for signing.`);
        console.log(`               RPs start caching it (overlap begins).`);
        console.log(`  Activate:    Start signing new tokens with this key.`);
        console.log(`  Deactivate:  Stop signing new tokens. Old tokens still verify`);
        console.log(`               because the public key is still in the JWKS.`);
        console.log(`  Remove:      Remove from JWKS after max-age + token TTL.`);
        console.log(`               All old tokens have expired or caches refreshed.`);
        console.log();

        await pause();

        console.log(`  Comparison Table`);
        console.log();
        console.log(`  ┌─────────────────────────┬────────────────────┬───────────────────────┐`);
        console.log(`  │  Scenario               │  Availability      │  Integrity            │`);
        console.log(`  ├─────────────────────────┼────────────────────┼───────────────────────┤`);
        console.log(`  │  Normal rotation         │  ✅ No disruption  │  ✅ Secure             │`);
        console.log(`  │  (overlap >= ${(maxAge + tokenTTL) / 3600}h)       │  All tokens verify │  Orderly transition   │`);
        console.log(`  ├─────────────────────────┼────────────────────┼───────────────────────┤`);
        console.log(`  │  Too-fast rotation       │  ✗ Self-inflicted  │  ✅ Secure             │`);
        console.log(`  │  (overlap < max-age)     │  outage — valid    │  No compromise, just  │`);
        console.log(`  │                         │  tokens rejected   │  operational error    │`);
        console.log(`  ├─────────────────────────┼────────────────────┼───────────────────────┤`);
        console.log(`  │  Compromised — graceful  │  ✅ No disruption  │  ✗ BREACHED           │`);
        console.log(`  │  (keep compromised key) │  Users unaffected  │  Forged tokens        │`);
        console.log(`  │                         │                    │  accepted             │`);
        console.log(`  ├─────────────────────────┼────────────────────┼───────────────────────┤`);
        console.log(`  │  Compromised — immediate│  ✗ Users must      │  ✅ Secure             │`);
        console.log(`  │  (remove key NOW)       │  re-authenticate   │  Forged tokens        │`);
        console.log(`  │                         │                    │  rejected             │`);
        console.log(`  └─────────────────────────┴────────────────────┴───────────────────────┘`);
        console.log();
        console.log(`  Cache-Control formula: overlap >= max-age + token_TTL`);
        console.log(`  With max-age=${maxAge}s and TTL=${tokenTTL}s: overlap >= ${maxAge + tokenTTL}s (${(maxAge + tokenTTL) / 3600} hours)`);
      },
    },
  ]);

  console.log();
  await pause();

  // ── Summary Card ────────────────────────────────────────────

  console.log(`╔══════════════════════════════════════════════════════════════════╗
║  SUMMARY CARD                                                    ║
║  Cover the answers below. Try to answer each from memory.        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Q: What is OIDC Discovery?                                      ║
║  A: JSON doc at .well-known/openid-configuration. RP learns      ║
║     issuer, endpoints, algorithms, jwks_uri. Fetched once,       ║
║     cached.                                                      ║
║                                                                  ║
║  Q: How does kid-based key selection work?                        ║
║  A: JWT header has "kid". RP finds matching key in JWKS.          ║
║     Multiple keys during rotation so both old and new tokens     ║
║     verify.                                                      ║
║                                                                  ║
║  Q: What's the safe key rotation overlap?                         ║
║  A: Overlap >= max-age + token TTL. Shorter = stale caches       ║
║     reject valid tokens. Old key stays until all caches          ║
║     refresh + all old tokens expire.                             ║
║                                                                  ║
║  Q: What if kid isn't in the JWKS?                                ║
║  A: Re-fetch JWKS (key may have been added). If still missing    ║
║     after re-fetch, reject. Never skip verification.             ║
║                                                                  ║
║  Q: Compromised key policy?                                       ║
║  A: Remove immediately. Force re-auth. Graceful rotation with    ║
║     a compromised key means knowingly accepting forged tokens.   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Draw a key rotation timeline: Key A is the current`);
  console.log(`     signing key, Key B is the new key. Label when B is added to`);
  console.log(`     the JWKS, when you start signing with B, when you remove A,`);
  console.log(`     and how Cache-Control max-age affects each step. Then explain`);
  console.log(`     what you'd do differently if Key A were compromised.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

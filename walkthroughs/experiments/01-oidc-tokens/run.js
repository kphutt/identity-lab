#!/usr/bin/env node

// Experiment 1: OIDC Token Anatomy + Confused Deputy
// Layer: Identity/Grant
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { createHash, randomBytes } from 'node:crypto';
import { createCLI, ensureDeps } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  await ensureDeps(import.meta.url);
  const jose = await import('jose');

  // Generate signing keypair
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);
  const kid = `key-${new Date().toISOString().slice(0, 10)}`;
  privateJwk.kid = kid;
  privateJwk.use = 'sig';
  privateJwk.alg = 'ES256';
  publicJwk.kid = kid;
  publicJwk.use = 'sig';
  publicJwk.alg = 'ES256';

  // Mock protocol values
  const accessToken = `mock-at-${randomBytes(16).toString('hex')}`;
  const authCode = `mock-code-${randomBytes(8).toString('hex')}`;
  const nonce = randomBytes(16).toString('hex');

  // Compute at_hash: SHA-256 the access token, take left 16 bytes, base64url encode
  const atHashDigest = createHash('sha256').update(accessToken).digest();
  const atHash = Buffer.from(atHashDigest.slice(0, 16)).toString('base64url');

  // Compute c_hash: same process for the authorization code
  const cHashDigest = createHash('sha256').update(authCode).digest();
  const cHash = Buffer.from(cHashDigest.slice(0, 16)).toString('base64url');

  const now = Math.floor(Date.now() / 1000);

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 1: OIDC Token Anatomy + Confused Deputy              ║
║  Layer: Identity/Grant                                           ║
║  Time: ~25 minutes                                               ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  This experiment constructs OIDC (OpenID Connect — an identity layer
  built on top of OAuth2) tokens from scratch. OAuth2 gives you an
  access token (authorization); OIDC adds an ID token that tells you
  WHO the user is (authentication).

  You'll build JWTs (JSON Web Tokens, pronounced "jot") — signed JSON
  payloads encoded as three base64url segments: header.payload.signature.
  The signature proves the token hasn't been tampered with.
`);
  await pause();

  // ── STEP 1: Generating the Signing Key ──────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: Generating the Signing Key

  Generating an EC P-256 (Elliptic Curve, NIST P-256) keypair...
  This is the recommended signing algorithm for modern OIDC — ES256
  (ECDSA with P-256 and SHA-256). RS256 is still common in older
  deployments (Azure AD, many legacy IdPs default to it).

  Private key (JWK — JSON Web Key, a standard JSON format for
  representing cryptographic keys):
  {
    "kty": "${privateJwk.kty}",
        ↳ Key Type. "EC" = Elliptic Curve. Tells the consumer which
          family of algorithms this key is for.

    "crv": "${privateJwk.crv}",
        ↳ Curve. "P-256" = NIST P-256 curve. Defines the key size
          and mathematical parameters.

    "x": "${privateJwk.x}",
        ↳ Public key X coordinate (base64url-encoded). Part of the
          public key — goes in the JWKS for verifiers to fetch.

    "y": "${privateJwk.y}",
        ↳ Public key Y coordinate (base64url-encoded). Together with
          x, these define the public point on the curve.

    "d": "${privateJwk.d}",
        ↳ Private key (base64url-encoded). NEVER leaves the
          authorization server. Never published in the JWKS.
          Anyone with "d" can sign tokens as this IdP.

    "kid": "${kid}",
        ↳ Key ID. Matches the kid in JWT headers to select this key
          from the JWKS. Used during key rotation to identify which
          key signed a given token.

    "use": "sig",
        ↳ Public Key Use. "sig" = this key is for signing (not
          encryption). Restricts what operations are valid.

    "alg": "ES256"
        ↳ Algorithm. Restricts this key to ES256 only. Prevents
          algorithm confusion attacks where an attacker tricks the
          verifier into using a different algorithm.
  }
`);
  await pause();

  // ── STEP 2: Constructing the JWKS ──────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: Constructing the JWKS

  JWKS (JSON Web Key Set) — a JSON document containing an array of
  public keys, published at a well-known URL (the jwks_uri) so RPs
  (Relying Parties — services that accept tokens) can fetch them
  for signature verification.

  Published at: https://idp.example.com/oauth/jwks
      ↳ The RP discovers this URL from the IdP's OIDC Discovery
        document at /.well-known/openid-configuration (covered
        in Experiment 6). The jwks_uri is NOT a well-known path
        itself — it can be any URL the IdP chooses.

  {
    "keys": [
        ↳ Array of public keys. The RP fetches this endpoint, finds
          the key matching the JWT's kid header, and uses it for
          signature verification. Multiple keys appear during key
          rotation (see Experiment 6).
      {
        "kty": "${publicJwk.kty}",
        "crv": "${publicJwk.crv}",
        "x":   "${publicJwk.x}",
        "y":   "${publicJwk.y}",
        "kid": "${kid}",
        "use": "sig",
        "alg": "ES256"
      }
    ]
  }

  Notice: NO "d" parameter. The JWKS only contains public keys.
  The private key stays on the authorization server.
`);
  await pause();

  // ── STEP 3: JWT Header ─────────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: Constructing the JWT Header

  The header tells verifiers HOW to verify this token.

  {
    "alg": "ES256",
        ↳ Algorithm. "ES256" = ECDSA with P-256 and SHA-256.
          Tells the verifier which algorithm to use for signature
          verification. Must match the key's alg in the JWKS.

    "typ": "JWT",
        ↳ Type. "JWT" for ID tokens. Access tokens use "at+jwt"
          (per RFC 9068). Resource servers use this to reject ID
          tokens presented as access tokens.

    "kid": "${kid}"
        ↳ Key ID. Identifies WHICH key in the JWKS was used to sign
          this token. The verifier fetches the JWKS, finds the key
          matching this kid, and uses it for verification.
  }
`);
  await pause();

  // ── STEP 4: ID Token Payload ────────────────────────────────

  const payload = {
    iss: 'https://idp.example.com',
    sub: 'user-8492',
    aud: 'client-app-xyz',
    azp: 'client-app-xyz',
    nonce,
    at_hash: atHash,
    c_hash: cHash,
    auth_time: now - 30,
    exp: now + 3600,
    iat: now,
    acr: 'urn:mace:incommon:iap:silver',
    amr: ['hwk', 'face'],
  };

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 4: Constructing the ID Token Payload (Claims)

  Every claim annotated. This is the identity assertion — it tells
  the RP (Relying Party) who the user is and how they authenticated.

  {
    "iss": "https://idp.example.com",
        ↳ Issuer. Who created this token. The RP checks this matches
          the IdP (Identity Provider — the service that authenticates
          users and issues tokens) it trusts. If it doesn't match,
          reject immediately — the token is from an unknown source.

    "sub": "user-8492",
        ↳ Subject. WHO THE USER IS. Stable, unique identifier at this
          IdP. Not an email — emails get reassigned. Federated account
          linking uses iss+sub, never email.

    "aud": "client-app-xyz",
        ↳ Audience. WHO THIS TOKEN IS FOR. In an ID token, aud MUST
          be the client_id of the RP that requested authentication
          (OIDC Core §2). The RP checks: "is aud MY client_id?"
          If not, REJECT. (In access tokens per RFC 9068, aud can
          be a resource server URL — don't confuse the two.)

    "azp": "client-app-xyz",
        ↳ Authorized Party. WHO REQUESTED this token. When aud has
          multiple values, azp identifies the specific client. If aud
          is a single value and matches azp, azp is optional.

    🎯 INTERVIEW ALERT: "What's the difference between sub and aud?"
       sub = the user's identity (WHO is authenticated)
       aud = the token's intended recipient (WHO should accept it)
       Confusing them is the confused deputy vulnerability.

    "nonce": "${nonce}",
        ↳ A random value the client sends in the auth request and
          expects back in the ID token. Prevents replay attacks.
          Different from PKCE: nonce protects the ID token,
          PKCE protects the auth code (see Experiment 4).

    🎯 INTERVIEW ALERT: "What's the difference between nonce and PKCE?"
       nonce binds the ID token to the auth request (replay prevention).
       PKCE binds the auth code to the client (interception prevention).
       They protect different artifacts at different protocol steps.

    "at_hash": "${atHash}",
        ↳ Access Token Hash. Left half of SHA-256 hash of the access
          token, base64url-encoded (${atHashDigest.length} byte hash → left
          16 bytes → base64url). Binds the ID token to its companion
          access token so they can't be mixed and matched.

    "c_hash": "${cHash}",
        ↳ Code Hash. Same as at_hash but for the authorization code.
          Binds the ID token to the code in the hybrid flow.

    "auth_time": ${payload.auth_time},
        ↳ When the user actually authenticated (Unix timestamp).
          RP checks this to enforce max_age: "don't accept logins
          older than X seconds."

    "exp": ${payload.exp},
        ↳ Expiration Time (Unix timestamp). After this moment, REJECT
          unconditionally. Short TTLs limit blast radius of token theft.

    "iat": ${payload.iat},
        ↳ Issued At. When this token was created. Used for freshness
          checks and audit trails.

    "acr": "urn:mace:incommon:iap:silver",
        ↳ Authentication Context Class Reference. The assurance level
          the IdP claims for this login. RP uses it for step-up auth
          policy: "this operation requires at least 'silver' assurance."

    "amr": ["hwk", "face"]
        ↳ Authentication Methods References. HOW the user actually
          authenticated. "hwk" = hardware key, "face" = biometric.
          This is the audit trail — acr is the policy classification.

    🎯 INTERVIEW ALERT: "What's the difference between acr and amr?"
       acr = assurance level (policy classification)
       amr = specific methods used (audit trail)
       RP requests minimum acr; IdP returns what it achieved + amr.
  }
`);
  await pause();

  // ── STEP 5: Signing the JWT ─────────────────────────────────

  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid })
    .sign(privateKey);

  const [headerB64, payloadB64, signatureB64] = jwt.split('.');

  // Wrap the JWT for display
  const WRAP = 66;
  const jwtLines = [];
  for (let i = 0; i < jwt.length; i += WRAP) {
    jwtLines.push(jwt.slice(i, i + WRAP));
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 5: Signing the JWT

  A JWT is three base64url-encoded segments separated by dots:
  header.payload.signature

  Encoding the header and payload as base64url...

  Header (base64url):
  ${headerB64}

  Payload (base64url):
  ${payloadB64}

  Now signing: ECDSA-SHA256(base64url(header) + "." + base64url(payload))
  using the private key...

  Signature (base64url):
  ${signatureB64}

  Complete JWT (${jwt.length} characters):
${jwtLines.map(l => '  ' + l).join('\n')}

  The three parts: header.payload.signature
  Anyone can decode the header and payload (they're just base64url).
  Only the IdP can produce a valid signature (requires the private key).
`);
  await pause();

  // ── STEP 6: Validation Walkthrough ──────────────────────────

  // Manually decode for display
  const decodedHeader = JSON.parse(
    Buffer.from(headerB64, 'base64url').toString()
  );

  // Verify the token for real
  const { payload: verifiedPayload } = await jose.jwtVerify(jwt, publicKey, {
    issuer: 'https://idp.example.com',
    audience: 'client-app-xyz',
  });

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 6: Validation Walkthrough

  The RP receives this JWT and must validate every aspect. Each
  check catches a different class of attack.

  1. Decode the header (base64url → JSON):
     alg: "${decodedHeader.alg}"  typ: "${decodedHeader.typ}"  kid: "${decodedHeader.kid}"
     ✓ Header decoded

  2. Fetch the JWKS from the IdP's jwks_uri
     Find the key matching kid="${kid}"
     ✓ Key found

  3. Verify the signature using the public key
     ECDSA-SHA256 verification against the fetched key...
     ✓ Signature valid

  4. Check iss matches the trusted IdP
     "${verifiedPayload.iss}" === "https://idp.example.com"
     ✓ Issuer trusted

  5. Check aud matches THIS client's client_id
     "${verifiedPayload.aud}" === "client-app-xyz"
     ✓ Audience matches

  6. Check exp > current time
     ${verifiedPayload.exp} > ${now} (${verifiedPayload.exp - now}s remaining)
     ✓ Not expired

  7. Check iat is reasonable (not in the future)
     ${verifiedPayload.iat} <= ${now}
     ✓ Issued in the past

  8. Check nonce matches the value sent in the auth request
     "${verifiedPayload.nonce.slice(0, 16)}..." matches stored value
     ✓ Nonce valid

  9. Verify at_hash: SHA-256 the access token, take left 16 bytes
     Computed: "${atHash}" === "${verifiedPayload.at_hash}"
     ✓ Access token binding valid

  All checks passed. This token is valid and trustworthy.
`);
  await pause();

  // ── STEP 7: Token Validation Lab (Exploration Point) ────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 7: Token Validation Lab

  You have a valid token for Service A. Let's see what happens
  when different validation checks fail — or get skipped.`);

  // Pre-generate a second keypair for the wrong-key scenario
  const { publicKey: wrongPublicKey } = await jose.generateKeyPair('ES256');

  await explore('Pick a scenario to explore:', [
    {
      name: 'Skip audience check',
      fn: async () => {
        console.log(`  Token aud:  "client-app-xyz" (Service A's client_id)`);
        console.log(`  You are:    "client-app-serviceB" (Service B's client_id)`);
        console.log();
        console.log(`  Signature ✓  Expiry ✓  Issuer ✓  Audience... not checked.`);
        console.log();
        console.log(`  Result: ACCEPTED ⚠️`);
        console.log();
        console.log(`  This is the confused deputy attack. Service A obtained a valid`);
        console.log(`  token for its own audience, then forwarded it to Service B.`);
        console.log(`  Without audience validation, Service B can't distinguish "user`);
        console.log(`  authenticated with me" from "another service relaying someone`);
        console.log(`  else's token."`);
        console.log();
        console.log(`  The fix: always check aud matches YOUR service identifier.`);
        console.log(`  Cross-service calls use token exchange (RFC 8693) to get a`);
        console.log(`  new token with the correct audience.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "What's the confused deputy problem?"`);
        console.log(`     A middle service forwards a token to a downstream service.`);
        console.log(`     Without aud checking, the downstream accepts it. The fix is`);
        console.log(`     audience validation + token exchange for cross-service calls.`);
      },
    },
    {
      name: 'Accept an expired token',
      fn: async () => {
        const pastExp = now - 3600;

        // Build an expired token using CompactSign to bypass SignJWT exp guard
        const expiredPayload = { ...payload, exp: pastExp, iat: now - 7200 };
        const expiredHeader = { alg: 'ES256', typ: 'JWT', kid };
        const expiredJwt = await new jose.CompactSign(
          new TextEncoder().encode(JSON.stringify(expiredPayload))
        )
          .setProtectedHeader(expiredHeader)
          .sign(privateKey);

        console.log(`  Token exp: ${pastExp} (1 hour ago)`);
        console.log(`  Current:   ${now}`);
        console.log();

        try {
          await jose.jwtVerify(expiredJwt, publicKey, {
            issuer: 'https://idp.example.com',
            audience: 'client-app-xyz',
          });
          console.log(`  Result: ACCEPTED (unexpected!)`);
        } catch (e) {
          console.log(`  Signature ✓  Issuer ✓  Audience ✓  Expiry... ${now - pastExp} seconds past.`);
          console.log();
          console.log(`  Result: REJECTED ✅`);
          console.log();
          console.log(`  Error: "${e.message}"`);
        }

        console.log();
        console.log(`  Even with a valid signature and correct audience, expired tokens`);
        console.log(`  MUST be rejected. Short-lived tokens limit the blast radius of`);
        console.log(`  theft. If you accept expired tokens, a stolen token is useful`);
        console.log(`  forever.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "Why not just use long-lived tokens?"`);
        console.log(`     Shorter TTL = smaller theft window. The tradeoff: too short =`);
        console.log(`     constant re-auth. CAEP (Continuous Access Evaluation Protocol,`);
        console.log(`     Experiment 8) closes the gap — revoke in real time instead of`);
        console.log(`     waiting for expiry.`);
      },
    },
    {
      name: 'Verify with the wrong key',
      fn: async () => {
        console.log(`  Token was signed with key: "${kid}"`);
        console.log(`  Verifying with a DIFFERENT key (simulating botched rotation)...`);
        console.log();

        try {
          await jose.jwtVerify(jwt, wrongPublicKey, {
            issuer: 'https://idp.example.com',
            audience: 'client-app-xyz',
          });
          console.log(`  Result: ACCEPTED (unexpected!)`);
        } catch (e) {
          console.log(`  Signature ✗  (verification failed)`);
          console.log();
          console.log(`  Result: REJECTED ✅`);
          console.log();
          console.log(`  Error: "${e.message}"`);
        }

        console.log();
        console.log(`  This is what happens during botched key rotation. If the IdP`);
        console.log(`  rotates to a new signing key but the JWKS hasn't propagated`);
        console.log(`  to all RPs yet (or the old key was removed from the JWKS too`);
        console.log(`  quickly), RPs verify against the wrong key and reject valid`);
        console.log(`  tokens. See Experiment 6 for the full key rotation lifecycle.`);
      },
    },
    {
      name: 'Accept token from untrusted issuer',
      fn: async () => {
        console.log(`  Token iss:    "https://idp.example.com"`);
        console.log(`  Trusted IdP:  "https://auth.mycompany.com"`);
        console.log();

        try {
          await jose.jwtVerify(jwt, publicKey, {
            issuer: 'https://auth.mycompany.com',
            audience: 'client-app-xyz',
          });
          console.log(`  Result: ACCEPTED (unexpected!)`);
        } catch {
          console.log(`  Signature ✓  Expiry ✓  Audience ✓  Issuer... MISMATCH.`);
          console.log();
          console.log(`  Result: REJECTED ✅`);
        }

        console.log();
        console.log(`  Issuer validation defines your trust boundary. Accepting`);
        console.log(`  tokens from unknown issuers means anyone who can run an IdP`);
        console.log(`  can assert identity to your service. The RP must maintain a`);
        console.log(`  strict list of trusted issuers and reject everything else.`);
      },
    },
    {
      name: 'Continue (all checks passing)',
      fn: async () => {
        // Full validation chain
        const { payload: verified } = await jose.jwtVerify(jwt, publicKey, {
          issuer: 'https://idp.example.com',
          audience: 'client-app-xyz',
        });

        console.log(`  Full validation chain — all checks passing:`);
        console.log();
        console.log(`  1. Decode header              ✓  alg=ES256, kid=${kid}`);
        console.log(`  2. Fetch JWKS, find kid       ✓  Key found`);
        console.log(`  3. Verify signature            ✓  ECDSA-SHA256 valid`);
        console.log(`  4. Check iss                   ✓  "https://idp.example.com"`);
        console.log(`  5. Check aud                   ✓  "client-app-xyz"`);
        console.log(`  6. Check exp                   ✓  ${verified.exp - now}s remaining`);
        console.log(`  7. Check iat                   ✓  Not in the future`);
        console.log(`  8. Check nonce                 ✓  Matches auth request`);
        console.log(`  9. Verify at_hash              ✓  Binds to access token`);
        console.log();
        console.log(`  Token is valid. User "user-8492" authenticated at`);
        console.log(`  "https://idp.example.com" for client "client-app-xyz".`);
        console.log();

        await pause();

        // ── Token Exchange (RFC 8693) ──
        console.log(`  ── Token Exchange (RFC 8693) ──`);
        console.log();
        console.log(`  The CORRECT way to call another service: don't forward your`);
        console.log(`  token. Exchange it for a new one with the right audience.`);
        console.log();
        console.log(`  Service A needs to call Service B. It sends a token exchange`);
        console.log(`  request to the STS (Security Token Service — the server that`);
        console.log(`  performs token exchanges, often the same as the IdP):`);
        console.log();
        console.log(`  POST /oauth/token`);
        console.log(`  {`);
        console.log(`    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",`);
        console.log(`        ↳ Grant Type. This specific URN identifies the token`);
        console.log(`          exchange grant defined in RFC 8693.`);
        console.log();
        console.log(`    "subject_token": "${jwt.slice(0, 36)}...",`);
        console.log(`        ↳ Subject Token. The original token being exchanged.`);
        console.log(`          This is Service A's valid token for user-8492.`);
        console.log();
        console.log(`    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",`);
        console.log(`        ↳ Subject Token Type. Tells the STS what kind of token`);
        console.log(`          is being presented. Could also be id_token or jwt.`);
        console.log();
        console.log(`    "audience": "https://api.serviceB.com"`);
        console.log(`        ↳ Requested Audience. Who the NEW token should be for.`);
        console.log(`          The STS checks policy, then issues a token with`);
        console.log(`          aud=serviceB.`);
        console.log(`  }`);
        console.log();

        // Sign a real exchanged token to make it concrete
        const exchangedPayload = {
          iss: 'https://idp.example.com',
          sub: 'user-8492',
          aud: 'https://api.serviceB.com',
          exp: now + 300,
          iat: now,
          act: { sub: 'https://api.serviceA.com' },
        };
        const exchangedJwt = await new jose.SignJWT(exchangedPayload)
          .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid })
          .sign(privateKey);

        console.log(`  Response:`);
        console.log(`  {`);
        console.log(`    "access_token": "${exchangedJwt.slice(0, 36)}...",`);
        console.log(`        ↳ The new token. aud is now "https://api.serviceB.com".`);
        console.log(`          Service B will accept this because it's addressed to it.`);
        console.log();
        console.log(`    "token_type": "Bearer",`);
        console.log(`        ↳ Token type. "Bearer" here, but ideally "DPoP" for`);
        console.log(`          sender-constrained tokens (see Experiment 2).`);
        console.log();
        console.log(`    "expires_in": 300`);
        console.log(`        ↳ Short-lived. Exchanged tokens should have minimal TTL`);
        console.log(`          — just long enough for the downstream call.`);
        console.log(`  }`);
        console.log();
        console.log(`  The exchanged token's payload includes:`);
        console.log(`    sub: "user-8492"          — same user`);
        console.log(`    aud: "serviceB.com"       — correct audience for Service B`);
        console.log(`    act.sub: "serviceA.com"   — the actor (who requested the exchange)`);
        console.log();
        console.log(`  No confused deputy. Each service gets a token addressed to it.`);
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
║  Key structures: JWT header, JWT payload claims, JWK, JWKS       ║
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
║  Q: Why use iss+sub for account linking instead of email?        ║
║  A: Emails get reassigned. iss+sub is stable and unique.         ║
║     Federated identity linking must use immutable identifiers.   ║
║                                                                  ║
║  Q: What is token exchange and when do you use it?               ║
║  A: RFC 8693. Trade your token for a new one with the right aud. ║
║     Use it for cross-service calls instead of forwarding tokens. ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Close this terminal. Explain out loud what the`);
  console.log(`     confused deputy attack is, what field prevents it, and why`);
  console.log(`     token exchange (RFC 8693) is the right pattern for cross-`);
  console.log(`     service calls. Then come back and check your answer above.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

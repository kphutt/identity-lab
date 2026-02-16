#!/usr/bin/env node

// Experiment 2: The Sender-Constraint Story — DPoP + DBSC
// Layer: Binding
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import * as jose from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Key Generation ──────────────────────────────────────────

  // 1. IdP/AS signing key — signs access tokens (at+jwt)
  const { publicKey: idpPublicKey, privateKey: idpPrivateKey } = await jose.generateKeyPair('ES256');
  const idpPublicJwk = await jose.exportJWK(idpPublicKey);
  const idpKid = `idp-${new Date().toISOString().slice(0, 10)}`;
  idpPublicJwk.kid = idpKid;
  idpPublicJwk.use = 'sig';
  idpPublicJwk.alg = 'ES256';

  // 2. Client DPoP key — signs DPoP proofs (dpop+jwt)
  const { publicKey: clientPublicKey, privateKey: clientPrivateKey } = await jose.generateKeyPair('ES256');
  const clientPublicJwk = await jose.exportJWK(clientPublicKey);

  // 3. Mock TPM key — signs DBSC challenge responses
  const { publicKey: tpmPublicKey, privateKey: tpmPrivateKey } = await jose.generateKeyPair('ES256');
  const tpmPublicJwk = await jose.exportJWK(tpmPublicKey);

  // Compute JWK Thumbprint for cnf claim
  const jkt = await jose.calculateJwkThumbprint(clientPublicJwk, 'sha256');

  const now = Math.floor(Date.now() / 1000);

  // ── Pre-built Artifacts ─────────────────────────────────────

  // Bearer access token: signed JWT (at+jwt), NO cnf claim
  const bearerPayload = {
    iss: 'https://as.example.com',
    sub: 'user-8492',
    aud: 'https://api.example.com',
    scope: 'read write',
    exp: now + 3600,
    iat: now,
    jti: randomBytes(16).toString('hex'),
  };
  const bearerToken = await new jose.SignJWT(bearerPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: idpKid })
    .sign(idpPrivateKey);

  // DPoP-bound access token: same but WITH cnf.jkt
  const dpopBoundPayload = {
    ...bearerPayload,
    jti: randomBytes(16).toString('hex'),
    cnf: { jkt },
  };
  const dpopBoundToken = await new jose.SignJWT(dpopBoundPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: idpKid })
    .sign(idpPrivateKey);

  // ath: full SHA-256 of the DPoP-bound access token (32 bytes → 43 chars base64url)
  const athDigest = createHash('sha256').update(dpopBoundToken).digest();
  const ath = athDigest.toString('base64url');

  // Valid DPoP proof
  const dpopProofPayload = {
    jti: randomBytes(16).toString('hex'),
    htm: 'GET',
    htu: 'https://api.example.com/data',
    iat: now,
    ath,
  };
  const dpopProof = await new jose.SignJWT(dpopProofPayload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: clientPublicJwk,
    })
    .sign(clientPrivateKey);

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 2: The Sender-Constraint Story — DPoP + DBSC        ║
║  Layer: Binding                                                  ║
║  Time: ~30 minutes                                               ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  Through-line: "Nothing should be a bearer credential."

  In Experiment 1, you built OIDC tokens and learned that the access token
  (typ: \`at+jwt\`, from Experiment 1) authorizes API calls. But that token
  was a bearer credential — anyone who has it can use it. This experiment
  fixes that.
`);
  await pause();

  // ── STEP 1: The Bearer Problem ────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Decode bearer token for display
  const bearerDecoded = jose.decodeJwt(bearerToken);

  console.log(`
  STEP 1: The Bearer Problem

  A bearer token (per RFC 6750) grants access to whoever holds it — no
  questions asked. Like a house key: anyone who picks it up can walk in.
  The name comes from "the bearer of this token."

  Here's a standard access token (typ: \`at+jwt\`, from Experiment 1):

  {
    "iss": "${bearerDecoded.iss}",
        ↳ Issuer. The Authorization Server that issued this token.

    "sub": "${bearerDecoded.sub}",
        ↳ Subject. The user this token represents.

    "aud": "${bearerDecoded.aud}",
        ↳ Audience. The resource server that should accept this token.

    "scope": "${bearerDecoded.scope}",
        ↳ Scope. What this token is allowed to do.

    "exp": ${bearerDecoded.exp},
        ↳ Expiration. After this, reject unconditionally.

    "iat": ${bearerDecoded.iat},
        ↳ Issued At. When the AS created this token.

    "jti": "${bearerDecoded.jti}"
        ↳ JWT ID. Unique identifier for this token.
  }

  Notice what's MISSING: there is no \`cnf\` (confirmation) claim. Nothing
  binds this token to the client that requested it. If an attacker steals
  this token (network sniffing, log exposure, XSS), they can use it from
  any machine, any client, any location. Possession = access.

  🎯 INTERVIEW ALERT: "Why are bearer tokens dangerous?"
     A bearer token has no sender binding. Anyone who possesses it can
     use it. Theft (via logs, XSS, network interception) gives the
     attacker full access until the token expires.
`);
  await pause();

  // ── STEP 2: DPoP — Binding Tokens to Keys ─────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const dpopBoundDecoded = jose.decodeJwt(dpopBoundToken);

  console.log(`
  STEP 2: DPoP — Binding Tokens to Keys

  DPoP (Demonstrating Proof of Possession, RFC 9449) fixes the bearer
  problem. The client generates a keypair, includes the public key in
  token requests, and proves possession of the private key on every
  API call. A stolen token is useless without the client's key.

  Generating a client keypair for DPoP...

  Client public key (JWK — JSON Web Key, from Experiment 1):
  {
    "kty": "${clientPublicJwk.kty}",
    "crv": "${clientPublicJwk.crv}",
    "x":   "${clientPublicJwk.x}",
    "y":   "${clientPublicJwk.y}"
  }

  The AS computes a JWK Thumbprint (RFC 7638) — a SHA-256 hash of
  the canonical form of the public key — and embeds it in the token:

  JWK Thumbprint (jkt): ${jkt}

  Now the access token includes a \`cnf\` (confirmation) claim:

  {
    "iss": "${dpopBoundDecoded.iss}",
    "sub": "${dpopBoundDecoded.sub}",
    "aud": "${dpopBoundDecoded.aud}",
    "scope": "${dpopBoundDecoded.scope}",
    "exp": ${dpopBoundDecoded.exp},
    "iat": ${dpopBoundDecoded.iat},
    "jti": "${dpopBoundDecoded.jti}",

    "cnf": {
      "jkt": "${jkt}"
          ↳ JWK Thumbprint. A SHA-256 hash of the client's public key.
            The resource server computes the thumbprint from the DPoP
            proof's jwk header and checks it matches this value.
            This is the binding: the token says "I belong to key X"
            and the DPoP proof proves "I have key X."
    }
  }

  🎯 INTERVIEW ALERT: "How does DPoP bind a token to a client?"
     The AS puts a \`cnf.jkt\` (JWK Thumbprint) in the access token.
     On every API call, the client sends a DPoP proof signed with its
     private key. The RS computes the thumbprint from the proof's public
     key and checks it matches cnf.jkt. No matching key = rejected.
`);
  await pause();

  // ── STEP 3: Stolen Token Lab (Exploration Point) ──────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: Stolen Token Lab

  Let's see what happens when tokens get stolen. You'll try replaying
  tokens in different scenarios to see exactly what DPoP prevents.`);

  // Pre-generate artifacts for scenarios
  const { privateKey: attackerPrivateKey } = await jose.generateKeyPair('ES256');
  const attackerPublicJwk = await jose.exportJWK((await jose.generateKeyPair('ES256')).publicKey);

  await explore('Pick a scenario to explore:', [
    {
      name: 'Replay bearer token from different client',
      fn: async () => {
        console.log(`  Attacker stole the bearer access token from the network.`);
        console.log(`  They present it from a completely different machine.`);
        console.log();
        console.log(`  Resource server checks:`);
        console.log(`    1. Decode token                 ✓  Valid JWT`);
        console.log(`    2. Verify signature              ✓  Signed by trusted AS`);
        console.log(`    3. Check exp                     ✓  Not expired`);
        console.log(`    4. Check aud                     ✓  Matches this RS`);
        console.log(`    5. Check cnf claim               —  No cnf claim present`);
        console.log(`    6. Require DPoP proof?           —  Token is bearer, not required`);
        console.log();
        console.log(`  Result: ACCEPTED ⚠️`);
        console.log();
        console.log(`  The resource server has no way to know the token was stolen.`);
        console.log(`  There is no binding — no \`cnf\` claim, no proof required. The`);
        console.log(`  token works for anyone who holds it. This is the fundamental`);
        console.log(`  bearer problem: possession = access.`);
      },
    },
    {
      name: 'Replay DPoP-bound token without the proof',
      fn: async () => {
        console.log(`  Attacker stole the DPoP-bound access token (has cnf.jkt).`);
        console.log(`  They present just the token, without a DPoP proof header.`);
        console.log();
        console.log(`  Resource server checks:`);
        console.log(`    1. Decode token                 ✓  Valid JWT`);
        console.log(`    2. Verify signature              ✓  Signed by trusted AS`);
        console.log(`    3. Check exp                     ✓  Not expired`);
        console.log(`    4. Check cnf claim               ✓  cnf.jkt present`);
        console.log(`    5. Check DPoP proof header       ✗  NO DPoP header!`);
        console.log();
        console.log(`  Result: REJECTED ✅`);
        console.log();
        console.log(`  The token has a \`cnf.jkt\` claim, which tells the RS "this token`);
        console.log(`  requires proof of possession." Without a DPoP proof in the request`);
        console.log(`  header, the RS rejects immediately. The attacker has the token but`);
        console.log(`  can't produce a valid proof without the client's private key.`);
      },
    },
    {
      name: 'Replay DPoP-bound token with proof for wrong endpoint',
      fn: async () => {
        // Build a proof for a different endpoint
        const wrongProof = await new jose.SignJWT({
          jti: randomBytes(16).toString('hex'),
          htm: 'POST',
          htu: 'https://api.example.com/admin',
          iat: now,
          ath,
        })
          .setProtectedHeader({
            alg: 'ES256',
            typ: 'dpop+jwt',
            jwk: clientPublicJwk,
          })
          .sign(clientPrivateKey);

        const wrongProofDecoded = jose.decodeJwt(wrongProof);

        console.log(`  Attacker somehow obtained both the token AND a valid DPoP proof.`);
        console.log(`  They try to use the proof at a different endpoint.`);
        console.log();
        console.log(`  DPoP proof says:  htm="${wrongProofDecoded.htm}"  htu="${wrongProofDecoded.htu}"`);
        console.log(`  Actual request:   htm="GET"   htu="https://api.example.com/data"`);
        console.log();
        console.log(`  Resource server checks:`);
        console.log(`    1. Decode token                 ✓  Valid JWT`);
        console.log(`    2. Verify signature              ✓  Signed by trusted AS`);
        console.log(`    3. Decode DPoP proof             ✓  Valid dpop+jwt`);
        console.log(`    4. Verify proof signature         ✓  Signed by matching key`);
        console.log(`    5. Check cnf.jkt matches         ✓  Thumbprint matches proof jwk`);
        console.log(`    6. Check htm                     ✗  "POST" !== "GET"`);
        console.log(`    7. Check htu                     ✗  "/admin" !== "/data"`);
        console.log();
        console.log(`  Result: REJECTED ✅`);
        console.log();
        console.log(`  The DPoP proof is bound to a specific HTTP method and URL. Even`);
        console.log(`  if an attacker captures a valid proof, they can only replay it at`);
        console.log(`  the exact endpoint it was created for. Different method or URL`);
        console.log(`  means the proof is invalid.`);
      },
    },
    {
      name: 'Replay DPoP-bound token with proof using different access token',
      fn: async () => {
        // Build a second DPoP-bound token
        const secondToken = await new jose.SignJWT({
          ...dpopBoundPayload,
          jti: randomBytes(16).toString('hex'),
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: idpKid })
          .sign(idpPrivateKey);

        // ath of the second token
        const secondAth = createHash('sha256').update(secondToken).digest().toString('base64url');

        // Proof was made for the FIRST token (ath matches first token)
        // but attacker presents it with the SECOND token
        console.log(`  Attacker has two DPoP-bound tokens and a proof for one of them.`);
        console.log(`  They try to use the proof with a different access token.`);
        console.log();
        console.log(`  Proof's ath:  ${ath.slice(0, 22)}...`);
        console.log(`  Token's hash: ${secondAth.slice(0, 22)}...`);
        console.log();
        console.log(`  Resource server checks:`);
        console.log(`    1. Decode token                 ✓  Valid JWT`);
        console.log(`    2. Verify signature              ✓  Signed by trusted AS`);
        console.log(`    3. Decode DPoP proof             ✓  Valid dpop+jwt`);
        console.log(`    4. Verify proof signature         ✓  Signed by matching key`);
        console.log(`    5. Check cnf.jkt matches         ✓  Thumbprint matches proof jwk`);
        console.log(`    6. Check htm                     ✓  "GET" matches`);
        console.log(`    7. Check htu                     ✓  URL matches`);
        console.log(`    8. Check ath                     ✗  Hash doesn't match presented token!`);
        console.log();
        console.log(`  Result: REJECTED ✅`);
        console.log();
        console.log(`  The \`ath\` (access token hash) in the proof is a SHA-256 hash of`);
        console.log(`  the specific access token it was created for. Present a different`);
        console.log(`  token and the hash won't match. The proof is bound to one token.`);
      },
    },
    {
      name: 'Continue (summary + transition to DBSC)',
      fn: async () => {
        console.log(`  Summary of DPoP bindings — a stolen token is useless because`);
        console.log(`  the proof binds to ALL of these:`);
        console.log();
        console.log(`    Binding          Field      What it prevents`);
        console.log(`    ───────────────  ─────────  ──────────────────────────────────`);
        console.log(`    Client's key     cnf.jkt    Token used by different client`);
        console.log(`    HTTP method      htm        Proof replayed at different method`);
        console.log(`    Target URL       htu        Proof replayed at different endpoint`);
        console.log(`    Moment in time   iat        Old proofs replayed later`);
        console.log(`    Specific token   ath        Proof used with different token`);
        console.log();
        console.log(`  An attacker needs the client's private key to produce a valid`);
        console.log(`  proof. Stealing the token alone is not enough.`);
        console.log();
        console.log(`  But there's a gap: what about session cookies? Even with DPoP,`);
        console.log(`  if an infostealer grabs the session cookie, the attacker gets a`);
        console.log(`  full session. We'll address that with DBSC in Step 6.`);
      },
    },
  ]);

  console.log();
  await pause();

  // ── STEP 4: Inside the DPoP Proof ─────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const dpopProofHeader = jose.decodeProtectedHeader(dpopProof);
  const dpopProofDecoded = jose.decodeJwt(dpopProof);

  // For comparison: at_hash from Experiment 1 (left-half SHA-256)
  const atHashExample = createHash('sha256').update(dpopBoundToken).digest();
  const atHashLeft = Buffer.from(atHashExample.slice(0, 16)).toString('base64url');

  console.log(`
  STEP 4: Inside the DPoP Proof

  The DPoP proof is itself a JWT — but with typ \`dpop+jwt\`, not \`at+jwt\`.
  It's signed by the CLIENT (not the AS), and the public key goes in the
  HEADER (not the payload). Let's examine every field.

  DPoP Proof Header:
  {
    "typ": "${dpopProofHeader.typ}",
        ↳ Type. "dpop+jwt" identifies this as a DPoP proof. Resource
          servers check this to distinguish proofs from access tokens.

    "alg": "${dpopProofHeader.alg}",
        ↳ Algorithm. Must match the client's key type. ES256 here
          because the client key is EC P-256.

    "jwk": {
      "kty": "${dpopProofHeader.jwk.kty}",
      "crv": "${dpopProofHeader.jwk.crv}",
      "x":   "${dpopProofHeader.jwk.x}",
      "y":   "${dpopProofHeader.jwk.y}"
    }
        ↳ The client's PUBLIC key, embedded in the protected header.
          The RS uses this to: (1) verify the proof signature, and
          (2) compute the JWK Thumbprint to check against cnf.jkt
          in the access token. The key is in the HEADER, not the
          payload — this is specific to DPoP.
  }

  DPoP Proof Payload:
  {
    "jti": "${dpopProofDecoded.jti}",
        ↳ JWT ID. Unique identifier for THIS proof. The server
          maintains a jti cache and rejects duplicates. This is
          replay prevention — each proof is single-use.

    "htm": "${dpopProofDecoded.htm}",
        ↳ HTTP Method. The proof is bound to this method. If the
          request is GET but the proof says POST, reject.

    "htu": "${dpopProofDecoded.htu}",
        ↳ HTTP Target URI. The proof is bound to this URL. Prevents
          a proof captured at /data from being replayed at /admin.

    "iat": ${dpopProofDecoded.iat},
        ↳ Issued At. The RS enforces a time window (typically seconds
          to minutes). Old proofs are rejected even if the jti is new.

    "ath": "${dpopProofDecoded.ath}"
        ↳ Access Token Hash. SHA-256 of the access token, base64url-
          encoded. Binds this proof to this specific token.

          CRITICAL — ath vs at_hash (from Experiment 1):
            ath     = full SHA-256    (32 bytes → ${ath.length} chars base64url)
            at_hash = left-half only  (16 bytes → ${atHashLeft.length} chars base64url)

          ath:     ${ath}
          at_hash: ${atHashLeft}

          at_hash (OIDC Core §3.2.2.9) takes the LEFT HALF for
          compactness in ID tokens. ath (RFC 9449 §4.2) uses the
          FULL hash for stronger binding in DPoP proofs.

          ath is ONLY in resource requests. At the token endpoint,
          the client doesn't have a token yet, so there's no ath.
  }

  🎯 INTERVIEW ALERT: "What's the difference between ath and at_hash?"
     at_hash = left-half of SHA-256 (16 bytes, 22 chars base64url),
     used in OIDC ID tokens for compactness.
     ath = full SHA-256 (32 bytes, ${ath.length} chars base64url),
     used in DPoP proofs for stronger binding.
     ath only appears in resource requests (not token requests).
`);
  await pause();

  // ── STEP 5: DPoP vs mTLS ─────────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 5: DPoP vs mTLS

  Both DPoP and mTLS (mutual TLS — both client and server present
  certificates during the TLS handshake) are sender-constraint
  mechanisms. Here's when to pick which:

                    DPoP                          mTLS
    ──────────────  ────────────────────────────  ────────────────────────────
    Layer           Application (HTTP header)     Transport (TLS)
    Works through   Proxies, CDNs, load           Breaks at TLS termination
      intermediaries  balancers — yes                (proxy/CDN strips client cert)
    Binding scope   Per-request (htm, htu, ath)   Per-connection
    Key storage     WebCrypto (browser's crypto   Certificate store / HSM
                      API — non-exportable keys
                      resist XSS extraction)
    Client type     Public clients (browsers,     Confidential clients
                      mobile, SPAs)                 (backend services)
    Deployment      Lightweight — just HTTP        Heavier — PKI, cert mgmt,
                      headers + JSON                 infrastructure changes
    FAPI 2.0        Allowed                       Allowed

  Pick DPoP for:  Browsers, mobile apps, SPAs, public OAuth2 clients.
  Pick mTLS for:  Backend-to-backend, machine-to-machine, high-security.

  FAPI 2.0 (Financial-grade API — see Experiment 4) makes sender-
  constrained tokens MANDATORY. You must use DPoP or mTLS — bearer
  tokens are not allowed.

  🎯 INTERVIEW ALERT: "DPoP vs mTLS — when do you pick which?"
     DPoP for public clients (browsers, mobile) — works through proxies,
     per-request binding, key in WebCrypto. mTLS for confidential clients
     (backend services) — transport-layer, per-connection, needs PKI.
     FAPI 2.0 requires one or the other.
`);
  await pause();

  // ── STEP 6: DBSC ──────────────────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 6: DBSC — Device Bound Session Credentials

  The gap: even with DPoP protecting access tokens, the SESSION COOKIE
  is still a bearer credential. An infostealer (malware that extracts
  cookies and tokens from the browser's storage — the standard way MFA
  gets bypassed in practice) grabs the cookie → full session hijack.

  The attacker doesn't need your password or MFA. They steal the cookie
  AFTER you've already authenticated. DPoP can't help here — the cookie
  isn't a JWT with a cnf claim.

  DBSC (Device Bound Session Credentials) fixes this by binding session
  cookies to the device's TPM (Trusted Platform Module — a hardware
  security chip that can generate and store keys; the private key never
  leaves the chip).

  Let's walk through the DBSC flow:
`);

  // ── DBSC Registration (steps 1-4) ──

  const sessionId = randomBytes(16).toString('hex');
  const cookieValue = randomBytes(32).toString('hex');

  console.log(`  ── Registration (binding the session to the device) ──
`);
  console.log(`  Step 1: User logs in successfully (password + MFA + WebAuthn, etc.)
`);
  console.log(`  Step 2: Browser calls the DBSC API → generates a keypair in the TPM`);
  console.log(`    [TPM] Generating EC P-256 keypair...`);
  console.log(`    [TPM] Private key stored in hardware — cannot be exported`);
  console.log(`    [TPM] Public key exported for registration:`);
  console.log(`    {`);
  console.log(`      "kty": "${tpmPublicJwk.kty}",`);
  console.log(`      "crv": "${tpmPublicJwk.crv}",`);
  console.log(`      "x":   "${tpmPublicJwk.x}",`);
  console.log(`      "y":   "${tpmPublicJwk.y}"`);
  console.log(`    }
`);
  console.log(`  Step 3: Browser sends the public key to the server`);
  console.log(`    POST /dbsc/register`);
  console.log(`    {`);
  console.log(`      "session_id": "${sessionId.slice(0, 16)}...",`);
  console.log(`      "public_key": { "kty": "EC", "crv": "P-256", ... }`);
  console.log(`    }
`);
  console.log(`  Step 4: Server stores the public key, issues a session cookie`);
  console.log(`    Set-Cookie: __session=${cookieValue.slice(0, 16)}...; Secure; HttpOnly; SameSite=Strict`);
  console.log(`    Server record: { session: "${sessionId.slice(0, 16)}...", bound_key: <public key> }
`);

  await pause();

  // ── DBSC Session Refresh (steps 5-7) ──

  const challenge = randomBytes(32).toString('hex');

  // Sign the challenge with the mock TPM key
  const challengeResponse = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify({
      challenge,
      session_id: sessionId,
      iat: now,
    }))
  )
    .setProtectedHeader({ alg: 'ES256', typ: 'dbsc+jwt' })
    .sign(tpmPrivateKey);

  console.log(`  ── Session Refresh (proving the device) ──
`);
  console.log(`  Step 5: Server sends a challenge in the response`);
  console.log(`    HTTP/1.1 401 Unauthorized`);
  console.log(`    DBSC-Challenge: ${challenge.slice(0, 32)}...
`);
  console.log(`  Step 6: Browser signs the challenge with the TPM private key`);
  console.log(`    [TPM] Signing challenge with hardware-bound private key...`);
  console.log(`    [TPM] Signature produced (private key never left the chip)`);
  console.log(`    POST /dbsc/refresh`);
  console.log(`    {`);
  console.log(`      "signed_challenge": "${challengeResponse.slice(0, 40)}..."`);
  console.log(`    }
`);
  console.log(`  Step 7: Server verifies signature against stored public key`);
  console.log(`    Verify signature with stored key... ✓`);
  console.log(`    Session refreshed. New cookie issued.
`);

  await pause();

  // ── DBSC Attack Scenario (step 8) ──

  console.log(`  ── Attack Scenario (why DBSC defeats infostealers) ──
`);
  console.log(`  Step 8: Attacker steals the session cookie with an infostealer`);
  console.log();
  console.log(`    Attacker's machine:`);
  console.log(`    Cookie: __session=${cookieValue.slice(0, 16)}...  ← stolen ✓`);
  console.log(`    TPM private key: ✗ (hardware-bound to victim's device)`);
  console.log();
  console.log(`    Attacker presents the stolen cookie to the server.`);
  console.log(`    Server responds with a DBSC challenge.`);
  console.log();
  console.log(`    [Attacker] Received challenge: ${challenge.slice(0, 32)}...`);
  console.log(`    [Attacker] Need to sign with TPM key...`);
  console.log(`    [Attacker] ✗ No TPM private key! Can't sign the challenge.`);
  console.log(`    [Attacker] Session refresh FAILED.`);
  console.log();
  console.log(`    Result: Cookie is USELESS without the device's TPM key.`);
  console.log();
  console.log(`  The stolen cookie expires shortly, and the attacker can't refresh`);
  console.log(`  it. DBSC turns session cookies from bearer credentials into device-`);
  console.log(`  bound credentials. The cookie alone is not enough — you need the`);
  console.log(`  hardware.`);
  console.log();
  console.log(`  Per-site key scoping: each site gets its own TPM keypair, so a`);
  console.log(`  compromised site can't use your key to impersonate you elsewhere.`);
  console.log(`  This also prevents cross-site tracking via key correlation.`);
  console.log();
  console.log(`  Status: W3C draft specification, Chrome implementation in progress.`);
  console.log();
  console.log(`  🎯 INTERVIEW ALERT: "Why is DBSC needed if you already have DPoP?"`);
  console.log(`     DPoP binds ACCESS TOKENS to the client's key, but session COOKIES`);
  console.log(`     remain bearer credentials. Infostealers steal cookies, not tokens.`);
  console.log(`     DBSC binds cookies to the device's TPM — stolen cookies can't be`);
  console.log(`     refreshed without the hardware key.`);
  console.log();

  await pause();

  // ── STEP 7: Nothing is Bearer ─────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 7: Nothing is Bearer

  The progression from bearer to fully bound:

    ┌─────────────────┐
    │  Bearer Token    │  Anyone who has it can use it.
    │  (RFC 6750)      │  Theft = full access.
    └────────┬────────┘
             │  Add DPoP (RFC 9449)
             ▼
    ┌─────────────────┐
    │  DPoP-Bound      │  Token bound to client's key.
    │  Access Token    │  Stolen token needs the key to use.
    └────────┬────────┘
             │  Add DBSC (W3C draft)
             ▼
    ┌─────────────────┐
    │  DBSC-Bound      │  Session bound to device TPM.
    │  Session         │  Stolen cookie can't be refreshed.
    └─────────────────┘

  "Nothing should be a bearer credential."

  Access tokens are bound by DPoP. Session cookies are bound by DBSC.
  Every credential is tied to something the attacker can't steal remotely.
`);
  await pause();

  // ── Summary Card ────────────────────────────────────────────

  console.log(`╔══════════════════════════════════════════════════════════════════╗
║  SUMMARY CARD                                                    ║
║  Cover the answers below. Try to answer each from memory.        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Q: What is a bearer token and why is it dangerous?              ║
║  A: A token that grants access to whoever holds it (RFC 6750).   ║
║     No sender binding — theft = full access until expiry.        ║
║                                                                  ║
║  Q: How does DPoP bind a token to a client?                      ║
║  A: AS puts cnf.jkt (JWK Thumbprint) in the access token.       ║
║     Client sends a DPoP proof (dpop+jwt) on every request.      ║
║     RS checks the proof's jwk thumbprint matches cnf.jkt.        ║
║                                                                  ║
║  Q: What is ath and when is it included?                         ║
║  A: Access Token Hash — full SHA-256 (32 bytes, 43 chars).       ║
║     Included in DPoP proofs for resource requests. NOT at the    ║
║     token endpoint (no token yet). Contrast: at_hash is left-    ║
║     half only (16 bytes, 22 chars) in OIDC ID tokens.            ║
║                                                                  ║
║  Q: DPoP vs mTLS — when do you pick which?                      ║
║  A: DPoP for public clients (browsers, mobile) — application     ║
║     layer, works through proxies. mTLS for confidential clients  ║
║     (backend) — transport layer, needs PKI. FAPI 2.0 requires   ║
║     one or the other.                                            ║
║                                                                  ║
║  Q: Why is DBSC needed if you already have DPoP?                 ║
║  A: DPoP binds access tokens, but session cookies are still      ║
║     bearer. Infostealers steal cookies after MFA. DBSC binds     ║
║     cookies to the device TPM — can't refresh without hardware.  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Close this terminal. Explain out loud how DPoP binds`);
  console.log(`     an access token to a client (mention cnf.jkt and the proof), and`);
  console.log(`     why DBSC is still needed even with DPoP. Then come back and check`);
  console.log(`     your answer against the summary card above.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

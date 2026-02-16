#!/usr/bin/env node

// Experiment 8: CAEP / Shared Signals Framework
// Layer: Enforcement
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { randomBytes } from 'node:crypto';
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  jwtVerify,
  createLocalJWKSet,
  decodeProtectedHeader,
} from 'jose';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Pre-built Artifacts ─────────────────────────────────────

  // Transmitter keypair for signing SETs
  const { publicKey: txPublicKey, privateKey: txPrivateKey } =
    await generateKeyPair('ES256');
  const txPublicJwk = await exportJWK(txPublicKey);
  const txKid = 'tx-key-' + randomBytes(4).toString('hex');
  txPublicJwk.kid = txKid;
  txPublicJwk.use = 'sig';
  txPublicJwk.alg = 'ES256';

  // Transmitter's published JWKS
  const transmitterJwks = { keys: [txPublicJwk] };

  // Random IDs
  const userId = 'user-' + randomBytes(4).toString('hex');
  const sessionId = 'sess-' + randomBytes(4).toString('hex');
  const credentialId = 'cred-' + randomBytes(4).toString('hex');

  // Timestamps and TTL
  const now = Math.floor(Date.now() / 1000);
  const tokenTTL = 600; // 10 minutes

  // Issuer and audience
  const issuer = 'https://idp.example.com';
  const audience = 'https://api.example.com';

  // ── SET Payloads (stored separately for annotated display) ──

  const sessionRevokedPayload = {
    iss: issuer,
    iat: now,
    jti: randomBytes(8).toString('hex'),
    aud: audience,
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
        subject: {
          format: 'opaque',
          id: sessionId,
        },
        event_timestamp: now,
        reason_admin: {
          en: 'User deprovisioned via SCIM DELETE',
        },
      },
    },
  };

  const credentialChangePayload = {
    iss: issuer,
    iat: now,
    jti: randomBytes(8).toString('hex'),
    aud: audience,
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/credential-change': {
        subject: {
          format: 'iss_sub',
          iss: issuer,
          sub: userId,
        },
        credential_type: 'webauthn',
        change_type: 'revoke',
        event_timestamp: now,
        reason_admin: {
          en: 'Passkey reported stolen — credential compromised',
        },
      },
    },
  };

  const tokenClaimsChangePayload = {
    iss: issuer,
    iat: now,
    jti: randomBytes(8).toString('hex'),
    aud: audience,
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/token-claims-change': {
        subject: {
          format: 'iss_sub',
          iss: issuer,
          sub: userId,
        },
        claims: {
          groups: ['engineering'],
        },
        event_timestamp: now,
        reason_admin: {
          en: 'User removed from admins group',
        },
      },
    },
  };

  // ── Sign all SETs as real JWTs ──────────────────────────────

  const setHeader = { alg: 'ES256', typ: 'secevent+jwt', kid: txKid };

  const sessionRevokedSET = await new SignJWT(sessionRevokedPayload)
    .setProtectedHeader(setHeader)
    .sign(txPrivateKey);

  const credentialChangeSET = await new SignJWT(credentialChangePayload)
    .setProtectedHeader(setHeader)
    .sign(txPrivateKey);

  const tokenClaimsChangeSET = await new SignJWT(tokenClaimsChangePayload)
    .setProtectedHeader(setHeader)
    .sign(txPrivateKey);

  // Stale access token — still says groups=["admins","engineering"]
  const staleAccessToken = await new SignJWT({
    iss: issuer,
    sub: userId,
    aud: audience,
    iat: now - 120,
    exp: now + tokenTTL - 120,
    groups: ['admins', 'engineering'],
    scope: 'read write',
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: txKid })
    .sign(txPrivateKey);

  // jti deduplication set
  const seenJtis = new Set();

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
${'═'.repeat(66)}
  Experiment 8: CAEP / Shared Signals Framework
  Layer: Enforcement
  Time: ~25 minutes

  Step through with ENTER. Use --no-pause for full dump.
${'═'.repeat(66)}

  CAEP solves the JWT revocation gap. Self-contained tokens can't be
  revoked until they expire — CAEP signals tell the resource server
  to drop the session NOW.

  Where Experiment 7 showed decoded SET payloads and said "you'll
  construct and sign these as real JWTs" — this experiment delivers.
  Real jose-signed SETs (typ: secevent+jwt), real verification against
  transmitter JWKS, and three distinct event types showing how lifecycle
  events trigger enforcement signals.

  Builds on: Experiment 1 (self-contained JWTs, exp/TTL)
             Experiment 2 (DPoP/DBSC session binding)
             Experiment 6 (JWKS/kid rotation)
             Experiment 7 (SCIM DELETE, revocation gap preview)
`);
  await pause();

  // ── STEP 1: SET Structure ─────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const decodedHeader = decodeProtectedHeader(sessionRevokedSET);

  console.log(`
  STEP 1: SET Structure — Security Event Token (RFC 8417)

  Key terms:

  Transmitter — the service that detects a security event and sends
    it. Example: IdP detects a user was deprovisioned via SCIM DELETE.

  Receiver — the service that acts on the event. Example: resource
    server revokes the user's sessions immediately.

  Stream — a configured delivery channel between a transmitter and
    receiver. The receiver subscribes to event types it cares about
    (session-revoked, credential-change, etc.).

  A SET (Security Event Token) is a JWT that carries a security event.
  Not an access grant — an event notification. It tells the receiver
  something happened.

  SET header (decoded from the real JWT above):

  {
    "typ": "${decodedHeader.typ}",
        ↳ Token type. "secevent+jwt" identifies this as a Security
          Event Token. Not "JWT" (generic) or "at+jwt" (access token).
          This is how receivers distinguish SETs from other JWTs.

    "alg": "${decodedHeader.alg}",
        ↳ Signing algorithm. ES256 = ECDSA with P-256 and SHA-256.
          Same algorithms as access tokens — SETs are signed JWTs.

    "kid": "${decodedHeader.kid}"
        ↳ Key ID. Which key in the transmitter's JWKS signed this SET.
          Same pattern as Experiment 6 — the receiver fetches the
          transmitter's JWKS and finds the key by kid to verify.
  }

  SET payload:

  {
    "iss": "${sessionRevokedPayload.iss}",
        ↳ Issuer. The transmitter's identifier — who detected and sent
          the event. The receiver checks this against a list of trusted
          transmitters.

    "iat": ${sessionRevokedPayload.iat},
        ↳ Issued At. When the SET was generated. May differ from when
          the event occurred (see event_timestamp below).

    "jti": "${sessionRevokedPayload.jti}",
        ↳ JWT ID. Unique identifier for this event. Receivers track
          seen jti values for deduplication — process each event
          exactly once, even if delivered twice.

    "aud": "${sessionRevokedPayload.aud}",
        ↳ Audience. The receiver's identifier — who should process
          this event. Receivers reject SETs not addressed to them.

    "events": {
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
          ↳ Event type URI. Globally unique identifier for this kind
            of event. The URI is the key; the value object contains
            event-specific details. Multiple event types can exist
            in one SET.

        "subject": {
          "format": "opaque",
          "id": "${sessionId}"
        },
            ↳ Subject. What this event is about — which session to
              revoke. "opaque" format = the ID is an opaque string
              (not an email or URI). Other formats: "email",
              "iss_sub" (issuer + subject pair).

        "event_timestamp": ${sessionRevokedPayload.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked'].event_timestamp},
            ↳ Event Timestamp. When the event actually occurred.
              May be before iat if there was a detection/delivery
              delay.

        "reason_admin": { "en": "User deprovisioned via SCIM DELETE" }
            ↳ Admin Reason. Human-readable explanation for audit logs.
              Localized — "en" key for English.
      }
    }
  }

  🎯 INTERVIEW ALERT: "What is a SET and how does it differ from an access token?"
     A SET (RFC 8417) is a JWT with typ "secevent+jwt" that carries an
     event notification, not an access grant. It tells the receiver
     something happened (session revoked, credential compromised, etc.).
     Access tokens authorize API calls; SETs trigger security actions.

  🎯 INTERVIEW ALERT: "What are SSF transmitters and receivers?"
     Transmitter detects a security event and pushes a SET. Receiver
     acts on it (e.g., kills session). They're connected by a stream —
     a configured delivery channel where the receiver subscribes to the
     event types it cares about.
`);
  await pause();

  // ── STEP 2: HTTP Push Delivery + Receiver Verification ────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 2: HTTP Push Delivery + Receiver Verification

  The transmitter pushes the SET to the receiver's endpoint:

  POST https://api.example.com/.well-known/sse/events
  Content-Type: application/secevent+jwt
      ↳ Not application/json. The body IS the JWT string — a compact
        serialized SET, not a JSON wrapper. The Content-Type tells the
        receiver to parse it as a Security Event Token.

  Body: ${sessionRevokedSET.substring(0, 40)}...
      ↳ The complete signed JWT. Three base64url-encoded parts:
        header.payload.signature

  The receiver MUST verify before acting. Six steps:`);
  console.log();

  // Step 1: Verify signature
  const jwksVerifier = createLocalJWKSet(transmitterJwks);
  const { payload: verifiedPayload, protectedHeader: verifiedHeader } =
    await jwtVerify(sessionRevokedSET, jwksVerifier, {
      issuer,
      audience,
    });
  console.log(`    ✅ Step 1: Verify SET signature against transmitter JWKS`);
  console.log(`       Used kid "${verifiedHeader.kid}" from transmitter's JWKS`);
  console.log(`       jose.jwtVerify() confirmed signature is valid`);
  console.log();

  // Step 2: Check issuer
  const issuerTrusted = verifiedPayload.iss === issuer;
  console.log(`    ✅ Step 2: Check iss is a trusted transmitter`);
  console.log(`       iss = "${verifiedPayload.iss}" — ${issuerTrusted ? 'trusted' : 'NOT trusted'}`);
  console.log();

  // Step 3: jti dedup
  const jtiValue = verifiedPayload.jti;
  const isDuplicate = seenJtis.has(jtiValue);
  seenJtis.add(jtiValue);
  console.log(`    ✅ Step 3: Check jti for deduplication`);
  console.log(`       jti = "${jtiValue}" — ${isDuplicate ? 'DUPLICATE (reject)' : 'first time seen (accept)'}`);
  console.log(`       Added to seen set (${seenJtis.size} event${seenJtis.size > 1 ? 's' : ''} tracked)`);
  console.log();

  // Step 4: Extract event URI
  const eventUris = Object.keys(verifiedPayload.events);
  console.log(`    ✅ Step 4: Extract event type URI`);
  console.log(`       Event: ${eventUris[0]}`);
  console.log(`       Receiver knows this is a session-revoked event`);
  console.log();

  // Step 5: Find subject
  const eventData = verifiedPayload.events[eventUris[0]];
  console.log(`    ✅ Step 5: Find session by subject`);
  console.log(`       format = "${eventData.subject.format}", id = "${eventData.subject.id}"`);
  console.log(`       Look up session "${eventData.subject.id}" in session store`);
  console.log();

  // Step 6: Kill session
  console.log(`    ✅ Step 6: Kill session immediately`);
  console.log(`       Session "${eventData.subject.id}" terminated.`);
  console.log(`       Next API call with this session → 401 Unauthorized.`);
  console.log(`       Gap: milliseconds, not minutes.`);
  console.log();

  console.log(`  All 6 steps completed. The session is dead within milliseconds`);
  console.log(`  of the SCIM DELETE that triggered the event.`);

  await pause();

  // ── STEP 3: Security Event Lab (Exploration Point) ────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: Security Event Lab

  Three event types, each triggered by a different lifecycle event.
  Real signed JWTs, real verification. Explore each scenario.`);

  await explore('Pick a scenario to explore:', [
    {
      name: 'Session revoked (deprovisioning)',
      fn: async () => {
        console.log(`  Session Revoked — Triggered by SCIM DELETE (Experiment 7)`);
        console.log();
        console.log(`  When the IdP processes DELETE /Users/${userId}, it emits a`);
        console.log(`  session-revoked SET to every downstream service that has an`);
        console.log(`  active session for this user.`);
        console.log();
        console.log(`  The complete signed SET JWT:`);
        console.log();
        console.log(`  ${sessionRevokedSET}`);
        console.log();

        const header = decodeProtectedHeader(sessionRevokedSET);
        console.log(`  Decoded header:`);
        console.log(`  {`);
        console.log(`    "typ": "${header.typ}",`);
        console.log(`        ↳ Security Event Token — not an access token, not a generic JWT.`);
        console.log(`    "alg": "${header.alg}",`);
        console.log(`        ↳ ECDSA with P-256. Same signing as access tokens.`);
        console.log(`    "kid": "${header.kid}"`);
        console.log(`        ↳ Key ID — look this up in the transmitter's JWKS to verify.`);
        console.log(`  }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${sessionRevokedPayload.iss}",`);
        console.log(`        ↳ Transmitter. The IdP that detected the deprovisioning.`);
        console.log(`    "iat": ${sessionRevokedPayload.iat},`);
        console.log(`        ↳ Issued At. When the SET was created.`);
        console.log(`    "jti": "${sessionRevokedPayload.jti}",`);
        console.log(`        ↳ Unique event ID. Track this for deduplication.`);
        console.log(`    "aud": "${sessionRevokedPayload.aud}",`);
        console.log(`        ↳ Audience. The downstream service receiving this event.`);
        console.log(`    "events": {`);
        console.log(`      "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {`);
        console.log(`          ↳ Event type URI — session-revoked.`);
        console.log(`        "subject": { "format": "opaque", "id": "${sessionId}" },`);
        console.log(`            ↳ The session to revoke. Opaque format = session ID string.`);
        console.log(`        "event_timestamp": ${sessionRevokedPayload.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked'].event_timestamp},`);
        console.log(`            ↳ When the deprovisioning happened.`);
        console.log(`        "reason_admin": { "en": "User deprovisioned via SCIM DELETE" }`);
        console.log(`            ↳ Audit trail. Why this session was revoked.`);
        console.log(`      }`);
        console.log(`    }`);
        console.log(`  }`);
        console.log();

        await pause();

        // Live verification
        console.log(`  Receiver verification (6 steps):`);
        console.log();

        const verifier = createLocalJWKSet(transmitterJwks);
        const { payload: vPayload, protectedHeader: vHeader } =
          await jwtVerify(sessionRevokedSET, verifier, { issuer, audience });

        console.log(`    ✅ 1. Signature verified against transmitter JWKS (kid: ${vHeader.kid})`);
        console.log(`    ✅ 2. Issuer "${vPayload.iss}" is trusted`);

        const jti1 = vPayload.jti;
        const dup1 = seenJtis.has(jti1);
        seenJtis.add(jti1);
        console.log(`    ✅ 3. jti "${jti1}" — ${dup1 ? 'already seen (would reject duplicate)' : 'first time (accepted)'}`);

        const uri1 = Object.keys(vPayload.events)[0];
        console.log(`    ✅ 4. Event: session-revoked`);
        console.log(`       URI: ${uri1}`);

        const subj1 = vPayload.events[uri1].subject;
        console.log(`    ✅ 5. Subject: session "${subj1.id}" (format: ${subj1.format})`);
        console.log(`    ✅ 6. Action: session "${subj1.id}" TERMINATED`);
        console.log();
        console.log(`  The session is dead. Next API call → 401 Unauthorized.`);
        console.log(`  Total time from SCIM DELETE to session kill: milliseconds.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "How does CAEP solve the JWT revocation gap?"`);
        console.log(`     When a user is deprovisioned (SCIM DELETE), the IdP pushes a`);
        console.log(`     session-revoked SET to the resource server. The receiver verifies`);
        console.log(`     the SET signature, finds the session, and kills it immediately —`);
        console.log(`     regardless of token expiry. Minutes → milliseconds.`);
      },
    },
    {
      name: 'Credential compromised',
      fn: async () => {
        console.log(`  Credential Compromised — Passkey Reported Stolen`);
        console.log();
        console.log(`  A user's passkey (from Experiment 3/5) is reported as stolen or`);
        console.log(`  compromised. The IdP emits a credential-change SET to revoke ALL`);
        console.log(`  sessions established using that credential.`);
        console.log();
        console.log(`  The complete signed SET JWT:`);
        console.log();
        console.log(`  ${credentialChangeSET}`);
        console.log();

        const header = decodeProtectedHeader(credentialChangeSET);
        console.log(`  Decoded header:`);
        console.log(`  {`);
        console.log(`    "typ": "${header.typ}",  "alg": "${header.alg}",  "kid": "${header.kid}"`);
        console.log(`  }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${credentialChangePayload.iss}",`);
        console.log(`    "iat": ${credentialChangePayload.iat},`);
        console.log(`    "jti": "${credentialChangePayload.jti}",`);
        console.log(`    "aud": "${credentialChangePayload.aud}",`);
        console.log(`    "events": {`);
        console.log(`      "https://schemas.openid.net/secevent/caep/event-type/credential-change": {`);
        console.log(`          ↳ Event type — credential-change. Different from session-revoked.`);
        console.log(`            The receiver knows to revoke by credential, not by session ID.`);
        console.log();
        console.log(`        "subject": {`);
        console.log(`          "format": "iss_sub",`);
        console.log(`              ↳ Subject format "iss_sub" — identifies the user by issuer +`);
        console.log(`                subject pair. Not a single session — the USER whose`);
        console.log(`                credential is compromised.`);
        console.log(`          "iss": "${issuer}",`);
        console.log(`          "sub": "${userId}"`);
        console.log(`        },`);
        console.log();
        console.log(`        "credential_type": "webauthn",`);
        console.log(`            ↳ What kind of credential. "webauthn" = passkey/FIDO2.`);
        console.log(`              Could also be "password", "x509", etc.`);
        console.log();
        console.log(`        "change_type": "revoke",`);
        console.log(`            ↳ What happened to it. "revoke" = credential invalidated.`);
        console.log(`              Could also be "create", "update", "delete".`);
        console.log();
        console.log(`        "event_timestamp": ${credentialChangePayload.events['https://schemas.openid.net/secevent/caep/event-type/credential-change'].event_timestamp},`);
        console.log(`        "reason_admin": { "en": "Passkey reported stolen — credential compromised" }`);
        console.log(`      }`);
        console.log(`    }`);
        console.log(`  }`);
        console.log();

        await pause();

        // Verification
        console.log(`  Receiver verification:`);
        console.log();

        const verifier = createLocalJWKSet(transmitterJwks);
        const { payload: vPayload, protectedHeader: vHeader } =
          await jwtVerify(credentialChangeSET, verifier, { issuer, audience });

        console.log(`    ✅ 1. Signature verified (kid: ${vHeader.kid})`);
        console.log(`    ✅ 2. Issuer "${vPayload.iss}" trusted`);

        const jti2 = vPayload.jti;
        const dup2 = seenJtis.has(jti2);
        seenJtis.add(jti2);
        console.log(`    ✅ 3. jti "${jti2}" — ${dup2 ? 'duplicate' : 'new (accepted)'}`);

        const uri2 = Object.keys(vPayload.events)[0];
        const evt2 = vPayload.events[uri2];
        console.log(`    ✅ 4. Event: credential-change`);
        console.log(`    ✅ 5. Subject: user "${evt2.subject.sub}" (format: ${evt2.subject.format})`);
        console.log(`    ✅ 6. Action: revoke ALL sessions for user "${evt2.subject.sub}"`);
        console.log(`       → credential_type: ${evt2.credential_type}`);
        console.log(`       → change_type: ${evt2.change_type}`);
        console.log();
        console.log(`  Not just one session — ALL sessions for this user are terminated.`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "Why revoke ALL sessions for a compromised credential?"`);
        console.log(`     Sessions derive from authentication. If the credential is`);
        console.log(`     compromised, every session it established is suspect. A stolen`);
        console.log(`     passkey means the attacker could have authenticated as this user`);
        console.log(`     — every resulting session must be treated as potentially`);
        console.log(`     attacker-controlled.`);
      },
    },
    {
      name: 'Token claims changed (role change)',
      fn: async () => {
        console.log(`  Token Claims Changed — Removed from Admins Group`);
        console.log();
        console.log(`  A user is removed from the "admins" group in the directory. But`);
        console.log(`  their access token (from Experiment 1) still has the old claims`);
        console.log(`  embedded — it says groups=["admins","engineering"].`);
        console.log();
        console.log(`  This is the embedded claims freshness problem.`);
        console.log();

        // Show stale access token
        const atHeader = decodeProtectedHeader(staleAccessToken);
        const atParts = staleAccessToken.split('.');
        const atPayload = JSON.parse(
          Buffer.from(atParts[1], 'base64url').toString(),
        );

        console.log(`  Stale access token (still in use):`);
        console.log(`  {`);
        console.log(`    "typ": "${atHeader.typ}",  "alg": "${atHeader.alg}",  "kid": "${atHeader.kid}"`);
        console.log(`  }`);
        console.log(`  {`);
        console.log(`    "iss": "${atPayload.iss}",`);
        console.log(`    "sub": "${atPayload.sub}",`);
        console.log(`    "groups": ${JSON.stringify(atPayload.groups)},`);
        console.log(`        ↳ STALE. This token still says the user is in "admins".`);
        console.log(`          The directory was updated, but the token was issued before`);
        console.log(`          the change. Self-contained JWTs embed claims at issuance.`);
        console.log(`    "exp": ${atPayload.exp}`);
        console.log(`        ↳ Doesn't expire for another ${Math.max(0, atPayload.exp - now)} seconds. Until then,`);
        console.log(`          this token grants admin access.`);
        console.log(`  }`);
        console.log();

        await pause();

        // Show the SET
        console.log(`  Token-claims-change SET (just received):`);
        console.log();
        console.log(`  ${tokenClaimsChangeSET}`);
        console.log();

        const setHdr = decodeProtectedHeader(tokenClaimsChangeSET);
        console.log(`  Decoded header:`);
        console.log(`  {`);
        console.log(`    "typ": "${setHdr.typ}",  "alg": "${setHdr.alg}",  "kid": "${setHdr.kid}"`);
        console.log(`  }`);
        console.log();
        console.log(`  Decoded payload:`);
        console.log(`  {`);
        console.log(`    "iss": "${tokenClaimsChangePayload.iss}",`);
        console.log(`    "iat": ${tokenClaimsChangePayload.iat},`);
        console.log(`    "jti": "${tokenClaimsChangePayload.jti}",`);
        console.log(`    "aud": "${tokenClaimsChangePayload.aud}",`);
        console.log(`    "events": {`);
        console.log(`      "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {`);
        console.log(`          ↳ Event type — token-claims-change. The receiver knows that`);
        console.log(`            embedded claims in the current token are now stale.`);
        console.log();
        console.log(`        "subject": { "format": "iss_sub", "iss": "${issuer}", "sub": "${userId}" },`);
        console.log(`        "claims": {`);
        console.log(`          "groups": ["engineering"]`);
        console.log(`        },`);
        console.log(`            ↳ Current claims. The SET carries the UPDATED group list.`);
        console.log(`              Compare: token says ["admins","engineering"]`);
        console.log(`                       SET says   ["engineering"]`);
        console.log(`              "admins" is gone.`);
        console.log();
        console.log(`        "event_timestamp": ${tokenClaimsChangePayload.events['https://schemas.openid.net/secevent/caep/event-type/token-claims-change'].event_timestamp},`);
        console.log(`        "reason_admin": { "en": "User removed from admins group" }`);
        console.log(`      }`);
        console.log(`    }`);
        console.log(`  }`);
        console.log();

        await pause();

        // Verification
        console.log(`  Receiver verification:`);
        console.log();
        const verifier = createLocalJWKSet(transmitterJwks);
        const { payload: vPayload } =
          await jwtVerify(tokenClaimsChangeSET, verifier, { issuer, audience });

        const uri3 = Object.keys(vPayload.events)[0];
        const evt3 = vPayload.events[uri3];
        const jti3 = vPayload.jti;
        seenJtis.add(jti3);

        console.log(`    ✅ Signature verified, iss trusted, jti new`);
        console.log(`    ✅ Event: token-claims-change`);
        console.log(`    ✅ Subject: user "${evt3.subject.sub}"`);
        console.log();
        console.log(`  Three options for the receiver:`);
        console.log();
        console.log(`  ┌─────────────────────┬────────────────────────────────────────────┐`);
        console.log(`  │  Option             │  What happens                              │`);
        console.log(`  ├─────────────────────┼────────────────────────────────────────────┤`);
        console.log(`  │  1. Force refresh   │  Reject current token, redirect to IdP    │`);
        console.log(`  │                     │  for a new token with updated claims.      │`);
        console.log(`  │                     │  Most correct. User experiences a brief    │`);
        console.log(`  │                     │  interruption.                             │`);
        console.log(`  ├─────────────────────┼────────────────────────────────────────────┤`);
        console.log(`  │  2. Revoke session  │  Kill the session entirely. User must      │`);
        console.log(`  │                     │  re-authenticate. Most aggressive.         │`);
        console.log(`  ├─────────────────────┼────────────────────────────────────────────┤`);
        console.log(`  │  3. Override locally│  Cache the SET's claims and use them       │`);
        console.log(`  │                     │  instead of the token's embedded claims.   │`);
        console.log(`  │                     │  Least disruptive but adds local state.    │`);
        console.log(`  └─────────────────────┴────────────────────────────────────────────┘`);
        console.log();
        console.log(`  The freshness problem: self-contained tokens embed claims at`);
        console.log(`  issuance. The real world changes — groups, roles, permissions.`);
        console.log(`  Without CAEP, the token's claims are correct only at the moment`);
        console.log(`  of issuance and potentially stale every second after.`);
      },
    },
    {
      name: 'No CAEP (static TTL only)',
      fn: async () => {
        console.log(`  No CAEP — Static TTL Only (The Revocation Gap)`);
        console.log();
        console.log(`  Token TTL = ${tokenTTL}s (${tokenTTL / 60} minutes)`);
        console.log(`  User deprovisioned at minute 2.`);
        console.log();
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  WITHOUT CAEP:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  min 0       Token issued (TTL = ${tokenTTL / 60} min)`);
        console.log(`              └─ JWT is self-contained, signed, valid for 10 min`);
        console.log();
        console.log(`  min 2       DELETE /Users/${userId}`);
        console.log(`              └─ User disabled in IdP. But downstream doesn't know.`);
        console.log();
        console.log(`  min 3       API call with token → ACCEPTED  ⚠️`);
        console.log(`              └─ Token signature valid, exp not reached.`);
        console.log();
        console.log(`  min 5       API call with token → ACCEPTED  ⚠️`);
        console.log(`              └─ Still valid. 3 minutes after termination.`);
        console.log();
        console.log(`  min 8       API call with token → ACCEPTED  ⚠️`);
        console.log(`              └─ 6 minutes after termination. Still full access.`);
        console.log();
        console.log(`  min 10      Token expires → REJECTED  ✅`);
        console.log(`              └─ Finally. 8 minutes of unauthorized access.`);
        console.log();
        console.log(`  Gap: 8 minutes of access after the user was terminated.`);
        console.log();

        await pause();

        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log(`  WITH CAEP:`);
        console.log(`  ──────────────────────────────────────────────────────────────`);
        console.log();
        console.log(`  min 0       Token issued (TTL = ${tokenTTL / 60} min)`);
        console.log();
        console.log(`  min 2       DELETE /Users/${userId}`);
        console.log(`              └─ User disabled in IdP.`);
        console.log();
        console.log(`  min 2.000   SET event emitted (session-revoked)`);
        console.log(`              └─ IdP pushes revocation signal to all downstream.`);
        console.log();
        console.log(`  min 2.001   Downstream receives SET → session killed  ✅`);
        console.log(`              └─ Token still technically "valid" but session is dead.`);
        console.log();
        console.log(`  min 3       API call with token → REJECTED  ✅`);
        console.log(`              └─ Session already terminated. Access denied.`);
        console.log();
        console.log(`  Gap: milliseconds. Not minutes — milliseconds.`);
        console.log();
        console.log(`  The math:`);
        console.log(`    Without CAEP: TTL (${tokenTTL / 60} min) − time elapsed (2 min) = ${(tokenTTL / 60) - 2} min gap`);
        console.log(`    With CAEP:    SET delivery + verification ≈ 1-10 ms`);
        console.log();
        console.log(`  🎯 INTERVIEW ALERT: "What is the JWT revocation gap?"`);
        console.log(`     Self-contained JWTs can't be revoked until they expire. With a`);
        console.log(`     ${tokenTTL / 60}-minute TTL and deprovisioning at minute 2, that's 8 minutes of`);
        console.log(`     unauthorized access. CAEP closes this gap to milliseconds by`);
        console.log(`     pushing real-time revocation signals to downstream services.`);
      },
    },
    {
      name: 'Continue (signal-based vs static lifetimes)',
      fn: async () => {
        console.log(`  Signal-Based vs Static Lifetimes`);
        console.log();
        console.log(`  ┌──────────────────────┬──────────────────────────┬──────────────────────────┐`);
        console.log(`  │                      │  Static TTL              │  CAEP (Signal-Based)     │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Revocation speed    │  Waits for token expiry. │  Milliseconds. SET       │`);
        console.log(`  │                      │  Gap = remaining TTL.    │  pushed immediately.     │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  TTL role            │  Security boundary.      │  Cache duration. How     │`);
        console.log(`  │                      │  Shorter = smaller gap   │  long to trust cached    │`);
        console.log(`  │                      │  but more re-auth load.  │  authz decision.         │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Infrastructure      │  None. Just JWTs with    │  Transmitter + receiver  │`);
        console.log(`  │                      │  exp claims.             │  + stream management.    │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Failure mode        │  Revocation gap.         │  If transmitter is down, │`);
        console.log(`  │                      │  Predictable but         │  events don't flow.      │`);
        console.log(`  │                      │  unavoidable.            │  Falls back to static.   │`);
        console.log(`  ├──────────────────────┼──────────────────────────┼──────────────────────────┤`);
        console.log(`  │  Best for            │  Simple systems. Low     │  Enterprise. Compliance  │`);
        console.log(`  │                      │  risk tolerance for      │  requires immediate      │`);
        console.log(`  │                      │  infra complexity.       │  revocation.             │`);
        console.log(`  └──────────────────────┴──────────────────────────┴──────────────────────────┘`);
        console.log();
        console.log(`  The tradeoff: static TTL is simpler (no event infrastructure) but has`);
        console.log(`  a revocation gap. CAEP eliminates the gap but requires transmitter/`);
        console.log(`  receiver infrastructure and stream management.`);
        console.log();

        await pause();

        console.log(`  Connection Map: Layer 4 (Lifecycle) → Layer 5 (Enforcement)`);
        console.log();
        console.log(`  Three trigger → event pairs showing how lifecycle events drive`);
        console.log(`  enforcement signals:`);
        console.log();
        console.log(`  ┌────────────────────────────────┐    ┌────────────────────────────────┐`);
        console.log(`  │  SCIM DELETE (Experiment 7)     │───▶│  session-revoked SET            │`);
        console.log(`  │  User deprovisioned             │    │  Kill session immediately       │`);
        console.log(`  └────────────────────────────────┘    └────────────────────────────────┘`);
        console.log();
        console.log(`  ┌────────────────────────────────┐    ┌────────────────────────────────┐`);
        console.log(`  │  Credential compromise          │───▶│  credential-change SET          │`);
        console.log(`  │  Passkey stolen/leaked           │    │  Revoke ALL sessions for user   │`);
        console.log(`  └────────────────────────────────┘    └────────────────────────────────┘`);
        console.log();
        console.log(`  ┌────────────────────────────────┐    ┌────────────────────────────────┐`);
        console.log(`  │  Role change in directory       │───▶│  token-claims-change SET        │`);
        console.log(`  │  Removed from "admins" group    │    │  Force refresh / revoke / cache  │`);
        console.log(`  └────────────────────────────────┘    └────────────────────────────────┘`);
        console.log();
        console.log(`  Layer 4 (Lifecycle/SCIM) detects the change.`);
        console.log(`  Layer 5 (Enforcement/CAEP) delivers the signal.`);
        console.log(`  Together: lifecycle events trigger immediate enforcement.`);
      },
    },
  ]);

  console.log();
  await pause();

  // ── Summary Card ────────────────────────────────────────────

  console.log(`${'═'.repeat(66)}
  SUMMARY CARD
  Cover the answers below. Try to answer each from memory.
${'═'.repeat(66)}

  Q: What is CAEP?
  A: Continuous Access Evaluation Protocol. Pushes real-time security
     events to close the JWT revocation gap (minutes to milliseconds).

  Q: What is a SET?
  A: Security Event Token (RFC 8417). A JWT with typ secevent+jwt
     carrying an event notification, not an access grant.

  Q: What are the 6 receiver verification steps?
  A: (1) Verify signature against transmitter JWKS.
     (2) Check iss is a trusted transmitter.
     (3) Check jti for deduplication.
     (4) Extract event type URI.
     (5) Find subject (session, user, credential).
     (6) Act immediately (kill session, revoke, refresh).

  Q: Why revoke ALL sessions for a compromised credential?
  A: Sessions derive from authentication. Compromised credential =
     every session it established is suspect.

  Q: Static TTL vs CAEP?
  A: Static: TTL is security boundary, gap = minutes.
     CAEP: TTL becomes cache duration, gap = milliseconds.
     CAEP needs transmitter/receiver infrastructure.

${'═'.repeat(66)}
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  PRACTICE: Close this terminal. Explain out loud what a Security`);
  console.log(`  Event Token is (typ, key fields, how it differs from an access`);
  console.log(`  token), the 6 steps a receiver takes to verify and act on one, and`);
  console.log(`  how CAEP closes the JWT revocation gap from minutes to milliseconds.`);
  console.log(`  Then come back and check.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

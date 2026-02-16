#!/usr/bin/env node

// Experiment 3: WebAuthn Ceremonies — Registration + Authentication
// Layer: Presence
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { createHash, randomBytes, generateKeyPairSync, sign, verify } from 'node:crypto';
import { encode as cborEncode, decode as cborDecode } from 'cbor-x';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Utility Functions ───────────────────────────────────────────

function flagsBreakdown(byte) {
  const bits = byte.toString(2).padStart(8, '0');
  const labels = [
    `  Bit 0 (UP — User Present):              ${(byte & 0x01) ? '1 ✓' : '0'}`,
    `  Bit 1 (RFU):                             ${(byte & 0x02) ? '1' : '0'}`,
    `  Bit 2 (UV — User Verified):              ${(byte & 0x04) ? '1 ✓' : '0'}`,
    `  Bit 3 (BE — Backup Eligible):            ${(byte & 0x08) ? '1' : '0'}`,
    `  Bit 4 (BS — Backup State):               ${(byte & 0x10) ? '1' : '0'}`,
    `  Bit 5 (RFU):                             ${(byte & 0x20) ? '1' : '0'}`,
    `  Bit 6 (AT — Attested Credential Data):   ${(byte & 0x40) ? '1 ✓' : '0'}`,
    `  Bit 7 (ED — Extension Data):             ${(byte & 0x80) ? '1' : '0'}`,
  ];
  return { bits, labels };
}

function buildCoseKey(publicKeyJwk) {
  const xBytes = Buffer.from(publicKeyJwk.x, 'base64url');
  const yBytes = Buffer.from(publicKeyJwk.y, 'base64url');
  // COSE key uses integer labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
  const coseMap = new Map([
    [1, 2],       // kty: EC2
    [3, -7],      // alg: ES256
    [-1, 1],      // crv: P-256
    [-2, xBytes], // x coordinate
    [-3, yBytes], // y coordinate
  ]);
  return cborEncode(coseMap);
}

function buildAuthenticatorData(opts) {
  const {
    rpId,
    flags,
    counter,
    aaguid,       // 16-byte Buffer (optional, for registration)
    credentialId, // Buffer (optional, for registration)
    coseKey,      // Buffer (optional, for registration)
  } = opts;

  const rpIdHash = createHash('sha256').update(rpId).digest();
  const flagsBuf = Buffer.from([flags]);
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter);

  const parts = [rpIdHash, flagsBuf, counterBuf];

  if (aaguid && credentialId && coseKey) {
    parts.push(aaguid);
    const credIdLenBuf = Buffer.alloc(2);
    credIdLenBuf.writeUInt16BE(credentialId.length);
    parts.push(credIdLenBuf);
    parts.push(credentialId);
    parts.push(coseKey);
  }

  return Buffer.concat(parts);
}

function buildAttestationObject(opts) {
  const { fmt, attStmt, authData } = opts;
  return cborEncode({ fmt, attStmt, authData });
}

// ── DER Construction Helpers ────────────────────────────────────

function derLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derSequence(...items) {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}

function derInteger(value) {
  let buf;
  if (typeof value === 'number') {
    // Encode small integers
    if (value < 0x80) {
      buf = Buffer.from([value]);
    } else {
      const hex = value.toString(16);
      buf = Buffer.from(hex.padStart(hex.length + (hex.length % 2), '0'), 'hex');
      if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
  } else {
    // Buffer
    buf = value;
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return Buffer.concat([Buffer.from([0x02]), derLength(buf.length), buf]);
}

function derOid(oidBytes) {
  return Buffer.concat([Buffer.from([0x06]), derLength(oidBytes.length), oidBytes]);
}

function derBitString(data) {
  const body = Buffer.concat([Buffer.from([0x00]), data]); // 0 unused bits
  return Buffer.concat([Buffer.from([0x03]), derLength(body.length), body]);
}

function derOctetString(data) {
  return Buffer.concat([Buffer.from([0x04]), derLength(data.length), data]);
}

function derExplicit(tag, data) {
  return Buffer.concat([Buffer.from([0xa0 | tag]), derLength(data.length), data]);
}

function derUtf8String(str) {
  const buf = Buffer.from(str, 'utf8');
  return Buffer.concat([Buffer.from([0x0c]), derLength(buf.length), buf]);
}

function derSet(...items) {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x31]), derLength(body.length), body]);
}

function buildSelfSignedCert(publicKey, privateKey, subject) {
  // OIDs
  const ecPublicKeyOid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // 1.2.840.10045.2.1
  const p256Oid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);   // 1.2.840.10045.3.1.7
  const sha256WithEcdsaOid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]); // 1.2.840.10045.4.3.2
  const commonNameOid = Buffer.from([0x55, 0x04, 0x03]); // 2.5.4.3

  // Export the raw public key point (uncompressed: 0x04 || x || y)
  const pubJwk = publicKey.export({ format: 'jwk' });
  const xBuf = Buffer.from(pubJwk.x, 'base64url');
  const yBuf = Buffer.from(pubJwk.y, 'base64url');
  const pubPoint = Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);

  // TBS (To Be Signed) Certificate
  const version = derExplicit(0, derInteger(2)); // v3
  const serialNumber = derInteger(randomBytes(8));
  const signatureAlgorithm = derSequence(derOid(sha256WithEcdsaOid));
  const issuerName = derSequence(derSet(derSequence(derOid(commonNameOid), derUtf8String(subject))));
  const subjectName = issuerName; // self-signed: issuer = subject

  // Validity: not before = now, not after = now + 1 year
  const now = new Date();
  const later = new Date(now.getTime() + 365 * 24 * 3600 * 1000);
  const formatTime = (d) => {
    const s = d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
    const buf = Buffer.from(s, 'ascii');
    return Buffer.concat([Buffer.from([0x17]), derLength(buf.length), buf]); // UTCTime
  };
  const validity = derSequence(formatTime(now), formatTime(later));

  const subjectPublicKeyInfo = derSequence(
    derSequence(derOid(ecPublicKeyOid), derOid(p256Oid)),
    derBitString(pubPoint)
  );

  const tbsCertificate = derSequence(
    version, serialNumber, signatureAlgorithm,
    issuerName, validity, subjectName, subjectPublicKeyInfo
  );

  // Sign
  const sig = sign('sha256', tbsCertificate, { key: privateKey, dsaEncoding: 'der' });

  // Full certificate
  const cert = derSequence(
    tbsCertificate,
    derSequence(derOid(sha256WithEcdsaOid)),
    derBitString(sig)
  );

  return cert;
}

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Key Generation ──────────────────────────────────────────

  // 1. Credential keypair — authenticator's per-credential key
  const credentialKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credentialPublicJwk = credentialKeyPair.publicKey.export({ format: 'jwk' });
  const credentialPrivateKey = credentialKeyPair.privateKey;

  // 2. Attestation keypair — mock manufacturer key for "packed" attestation
  const attestationKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const attestationPrivateKey = attestationKeyPair.privateKey;
  const attestationPublicKey = attestationKeyPair.publicKey;

  // ── Pre-built Artifacts ─────────────────────────────────────

  const rpId = 'example.com';
  const rpName = 'Example Corp';
  const rpIdHash = createHash('sha256').update(rpId).digest();

  const userId = randomBytes(16);
  const userName = 'alice@example.com';
  const userDisplayName = 'Alice';

  const challenge = randomBytes(32);
  const challengeB64 = challenge.toString('base64url');

  const credentialId = randomBytes(32);
  const credentialIdB64 = credentialId.toString('base64url');

  const aaguid = Buffer.from('f8a011f38c0a4d15800617111f9edc7d', 'hex'); // mock AAGUID

  const coseKeyBytes = buildCoseKey(credentialPublicJwk);

  // Registration authenticatorData (flags=0x41: UP + AT)
  const regFlags = 0x41;
  const regCounter = 0;
  const regAuthData = buildAuthenticatorData({
    rpId,
    flags: regFlags,
    counter: regCounter,
    aaguid,
    credentialId,
    coseKey: coseKeyBytes,
  });

  // Registration clientDataJSON
  const regClientData = {
    type: 'webauthn.create',
    challenge: challengeB64,
    origin: 'https://example.com',
    crossOrigin: false,
  };
  const regClientDataJSON = Buffer.from(JSON.stringify(regClientData));
  const regClientDataHash = createHash('sha256').update(regClientDataJSON).digest();

  // Attestation object (fmt: "none")
  const regAttestationObject = buildAttestationObject({
    fmt: 'none',
    attStmt: {},
    authData: regAuthData,
  });

  // Authentication artifacts
  const authChallenge = randomBytes(32);
  const authChallengeB64 = authChallenge.toString('base64url');
  const authFlags = 0x01; // UP only (no AT, no UV)
  const authCounter = 1;
  const authAuthData = buildAuthenticatorData({
    rpId,
    flags: authFlags,
    counter: authCounter,
  });

  const authClientData = {
    type: 'webauthn.get',
    challenge: authChallengeB64,
    origin: 'https://example.com',
    crossOrigin: false,
  };
  const authClientDataJSON = Buffer.from(JSON.stringify(authClientData));
  const authClientDataHash = createHash('sha256').update(authClientDataJSON).digest();

  // Sign: authData || SHA-256(clientDataJSON)
  const authSignedData = Buffer.concat([authAuthData, authClientDataHash]);
  const authSignature = sign('sha256', authSignedData, {
    key: credentialPrivateKey,
    dsaEncoding: 'ieee-p1363',
  });

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 3: WebAuthn Ceremonies — Registration + Auth         ║
║  Layer: Presence                                                 ║
║  Time: ~30 minutes                                               ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  Through-line: WebAuthn replaces passwords with public-key crypto.
  The browser mediates phishing resistance — credentials are bound to
  the origin, and neither the user nor the attacker can override it.

  WebAuthn (Web Authentication API) — a W3C standard that lets websites
  use public-key cryptography instead of passwords. FIDO2 is the umbrella
  term: WebAuthn (browser API) + CTAP2 (authenticator protocol).
`);
  await pause();

  // ── STEP 1: PublicKeyCredentialCreationOptions ─────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: PublicKeyCredentialCreationOptions

  The RP (Relying Party — the website requesting authentication) calls
  navigator.credentials.create() with these options. This is the starting
  point of the registration ceremony.

  {
    "rp": {
      "id": "${rpId}",
          ↳ RP ID. Typically the domain. Credentials are cryptographically
            bound to this value — a credential registered at bank.com
            cannot be used at evil.com. The authenticator checks this.

      "name": "${rpName}"
          ↳ Human-readable RP name. Shown on the authenticator's display
            (if it has one). Not used for security decisions.
    },

    "user": {
      "id": "${userId.toString('base64url')}",
          ↳ User handle. Opaque bytes, NOT the username. The authenticator
            stores this to identify which credential to use. Must be
            unique per user, stable across sessions.

      "name": "${userName}",
          ↳ Human-readable username. Displayed during credential selection.
            Can change (user renames account) — the user.id stays stable.

      "displayName": "${userDisplayName}"
          ↳ Friendly name. Shown on the authenticator prompt (e.g.,
            "Sign in as Alice"). Purely cosmetic.
    },

    "challenge": "${challengeB64}",
        ↳ Random bytes from the RP (min 16 bytes, here 32). The
          authenticator signs over this to prove freshness. Must be
          single-use — replay protection.

    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 }
          ↳ Algorithm preference. -7 = ES256 (ECDSA with P-256 and
            SHA-256, from Experiment 1). COSE (CBOR Object Signing and
            Encryption) uses integer codes: -7 for ES256, -257 for
            RS256. The RP lists what it supports; the authenticator
            picks one.
    ],

    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
          ↳ "platform" = built-in (Touch ID, Windows Hello).
            "cross-platform" = roaming (USB key, phone). Omit to
            allow either.

      "residentKey": "required",
          ↳ "required" = discoverable credential (stored on the
            authenticator, enables passwordless login without typing
            a username). "preferred" or "discouraged" for server-side
            credential storage.

      "userVerification": "preferred"
          ↳ "required" = must verify identity (biometric/PIN).
            "preferred" = verify if possible. "discouraged" = skip
            verification, presence only.
    },

    "attestation": "none"
        ↳ How much the RP wants to know about the authenticator.
          "none" = don't prove what you are (privacy-preserving).
          "direct" = send attestation certificate (enterprise use).
  }
`);
  await pause();

  // ── STEP 2: authenticatorData Binary Construction ─────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const regAuthDataHex = regAuthData.toString('hex');
  const { bits: flagsBits, labels: flagsLabels } = flagsBreakdown(regFlags);

  // COSE key field mapping
  const coseKeyDecoded = cborDecode(coseKeyBytes);

  console.log(`
  STEP 2: authenticatorData — Binary Construction

  The authenticator produces a binary blob. Every byte has meaning.
  CTAP2 (Client To Authenticator Protocol 2 — how the browser talks
  to the authenticator via CBOR over USB/NFC/BLE) defines this format.

  Building the authenticatorData byte-by-byte:

  Byte range   Field                Value
  ───────────  ───────────────────  ────────────────────────────────
  0-31         rpIdHash             SHA-256("${rpId}")
               ↳ ${rpIdHash.toString('hex').slice(0, 32)}...
                 The RP verifies this matches SHA-256 of its own rpId.
                 Binds this credential to this domain.

  32           flags                0x${regFlags.toString(16).padStart(2, '0')} (binary: ${flagsBits})
               ↳ Each bit is a flag:
${flagsLabels.map(l => '               ' + l).join('\n')}

  33-36        counter              ${regCounter} (big-endian uint32)
               ↳ Monotonically increasing. RP stores last-seen value.
                 If next auth has LOWER counter → possible clone.
                 This is the ONLY clone detection mechanism.

  37-52        AAGUID               ${aaguid.toString('hex')}
               ↳ Authenticator Attestation GUID. Identifies the
                 authenticator MODEL (not individual device). All
                 YubiKey 5 NFC devices share the same AAGUID. Look
                 this up in FIDO MDS (Metadata Service — a database
                 run by the FIDO Alliance with metadata for every
                 certified authenticator).

  53-54        credentialIdLength   ${credentialId.length} (big-endian uint16)
               ↳ Length of the credential ID that follows.

  55-${55 + credentialId.length - 1}        credentialId         ${credentialIdB64}
               ↳ Unique identifier for this credential. The RP stores
                 this and sends it back in allowCredentials during auth.

  ${55 + credentialId.length}+          COSE public key      (CBOR-encoded)
               ↳ The credential's public key in COSE format.

  COSE key (integer labels → human-readable):
    1 (kty)  → ${coseKeyDecoded.get(1)}   (2 = EC2, Elliptic Curve with x,y)
    3 (alg)  → ${coseKeyDecoded.get(3)}  (-7 = ES256, ECDSA with P-256)
   -1 (crv)  → ${coseKeyDecoded.get(-1)}   (1 = P-256)
   -2 (x)    → ${credentialPublicJwk.x}
   -3 (y)    → ${credentialPublicJwk.y}

  COSE → JWK bridge (connecting to Experiment 1):
    COSE kty=2 (EC2)     → JWK "kty": "EC"
    COSE alg=-7 (ES256)  → JWK "alg": "ES256"
    COSE crv=1 (P-256)   → JWK "crv": "P-256"
    COSE -2 (x bytes)    → JWK "x": "${credentialPublicJwk.x}"
    COSE -3 (y bytes)    → JWK "y": "${credentialPublicJwk.y}"

  🎯 INTERVIEW ALERT: "What is CTAP2 and how does it relate to WebAuthn?"
     CTAP2 (Client To Authenticator Protocol 2) is how the browser talks
     to the authenticator via CBOR over USB/NFC/BLE. The browser handles
     origin binding; the authenticator handles key generation and user
     verification. The authenticator never sees the origin; the browser
     never sees the private key.
`);
  await pause();

  // ── STEP 3: clientDataJSON ────────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: clientDataJSON — The Browser's Contribution

  The BROWSER constructs this JSON object — not the authenticator, not
  the RP. This is critical: the browser is the trusted intermediary.

  ${JSON.stringify(regClientData, null, 4).split('\n').map((line, i) => {
    if (i === 0) return '  ' + line;
    return '      ' + line;
  }).join('\n')}

  Field-by-field:

    "type": "webauthn.create"
        ↳ Ceremony type. "webauthn.create" for registration,
          "webauthn.get" for authentication. Set by the browser,
          not controllable by the RP or attacker.

    "challenge": "${challengeB64}"
        ↳ The RP's challenge, base64url-encoded by the browser.
          The RP checks this matches what it sent. Proves freshness.

    "origin": "https://example.com"
        ↳ THIS IS THE PHISHING DEFENSE. The browser sets this to
          the ACTUAL page URL — not what the page claims to be,
          not what the user thinks they're on, but the real origin.
          A phishing site at evil.com produces origin="https://evil.com".
          The RP checks: does this match my expected origin?
          Neither the user NOR the attacker can override this.

    "crossOrigin": false
        ↳ Whether the request came from a cross-origin iframe.
          Allows the RP to restrict credential use to same-origin
          contexts only.

  🎯 INTERVIEW ALERT: "How does WebAuthn prevent phishing?"
     The browser sets the origin field in clientDataJSON to the actual
     page URL — the user and attacker cannot override it. Additionally,
     credentials are bound to the rpId (domain). The authenticator won't
     use a credential registered at bank.com when asked by evil.com.
     Two independent bindings: origin (browser) + rpId (authenticator).
`);
  await pause();

  // ── STEP 4: attestationObject ─────────────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const attestObjHex = regAttestationObject.toString('hex');
  // Show first 80 chars of hex, then ...
  const attestObjHexDisplay = attestObjHex.length > 80
    ? attestObjHex.slice(0, 80) + '...'
    : attestObjHex;

  // Decode back for display
  const attestObjDecoded = cborDecode(regAttestationObject);

  console.log(`
  STEP 4: attestationObject — CBOR-Encoded Registration Response

  The attestationObject wraps the authenticatorData with attestation
  information. It's CBOR-encoded (CBOR — Concise Binary Object
  Representation, a binary encoding format like JSON but compact).

  Raw CBOR hex (${regAttestationObject.length} bytes):
  ${attestObjHexDisplay}

  Decoded structure:
  {
    "fmt": "${attestObjDecoded.fmt}",
        ↳ Attestation format. "none" = the authenticator doesn't prove
          what it is. Privacy-preserving — good for consumer sites.
          "packed" = standard attestation with optional cert chain.

    "attStmt": {},
        ↳ Attestation statement. Empty for fmt="none". For "packed"
          with x5c: contains { alg, sig, x5c: [cert, ...] }.
          The RP uses this to verify the authenticator's identity.

    "authData": <${regAuthData.length} bytes>
        ↳ The authenticatorData from Step 2. Contains rpIdHash, flags,
          counter, AAGUID, credentialId, and COSE public key.
  }

  The RP receives this CBOR blob, decodes it, and:
  1. Checks fmt — decides whether to verify attestation
  2. Extracts authData — parses the binary fields
  3. Stores credentialId + public key + counter for future auth
`);
  await pause();

  // ── STEP 5: Authentication Ceremony ───────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const { bits: authFlagsBits, labels: authFlagsLabels } = flagsBreakdown(authFlags);

  // Show the actual verification
  const verifyResult = verify(
    'sha256',
    authSignedData,
    { key: credentialKeyPair.publicKey, dsaEncoding: 'ieee-p1363' },
    authSignature
  );

  console.log(`
  STEP 5: Authentication Ceremony

  The user returns to sign in. The RP calls navigator.credentials.get()
  with a new challenge and the stored credentialId in allowCredentials.

  RP sends:
  {
    "challenge": "${authChallengeB64}",
        ↳ Fresh random bytes. Different from registration challenge.

    "allowCredentials": [
      { "type": "public-key", "id": "${credentialIdB64}" }
          ↳ The credential ID stored during registration. Tells the
            authenticator which credential to use.
    ],

    "userVerification": "preferred"
  }

  Authenticator responds with:

  authenticatorData (${authAuthData.length} bytes — shorter, no AT data):
    rpIdHash (0-31):  ${rpIdHash.toString('hex').slice(0, 32)}...
    flags (32):       0x${authFlags.toString(16).padStart(2, '0')} (binary: ${authFlagsBits})
                      UP=1, UV=0, AT=0 (no credential data in auth)
    counter (33-36):  ${authCounter} (was ${regCounter} at registration → incremented)

  clientDataJSON:
    type:       "webauthn.get"     (was "webauthn.create" during registration)
    challenge:  "${authChallengeB64.slice(0, 22)}..."
    origin:     "https://example.com"

  ── Signature Verification (step by step) ──

  The authenticator signs: authenticatorData || SHA-256(clientDataJSON)

  1. Hash the clientDataJSON (raw UTF-8 bytes, not re-serialized):
     SHA-256(clientDataJSON) = ${authClientDataHash.toString('hex').slice(0, 32)}...

  2. Concatenate authData || hash (byte order is CRITICAL):
     authData (${authAuthData.length} bytes) || hash (32 bytes) = ${authSignedData.length} bytes
     ${authSignedData.toString('hex').slice(0, 40)}...${authSignedData.toString('hex').slice(-16)}

  3. Signature (raw r||s, 64 bytes — NOT DER):
     ${authSignature.toString('hex').slice(0, 40)}...${authSignature.toString('hex').slice(-16)}

     WebAuthn uses ieee-p1363 format: raw r (32 bytes) || s (32 bytes).
     This is different from DER encoding used in X.509 certificates.

  4. Verify ECDSA signature with stored public key:
     Result: ${verifyResult ? '✓ Signature valid' : '✗ Signature invalid'}

  5. Check counter: ${authCounter} > ${regCounter} (stored)?
     ${authCounter > regCounter ? '✓ Counter increased — not a clone' : '✗ Counter did not increase'}

  All checks passed. User authenticated.

  🎯 INTERVIEW ALERT: "How does biometric authentication work in WebAuthn?"
     The authenticator matches the biometric locally — fingerprint or
     face never leaves the device. The RP only sees the UV bit (User
     Verified: yes/no). No biometric data is ever transmitted. The RP
     knows the user proved their identity, not how.
`);
  await pause();

  // ── STEP 6: RP Configuration Lab (Exploration Point) ──────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 6: RP Configuration Lab

  Different RP configurations produce different authenticatorData and
  attestation results. Explore how UV, attestation format, and counter
  behavior change the ceremony.`);

  // Pre-build artifacts for scenarios
  const uvRequiredFlags = 0x45; // UP + UV + AT
  const uvDiscouragedFlags = 0x41; // UP + AT (no UV)

  const uvRequiredAuthData = buildAuthenticatorData({
    rpId, flags: uvRequiredFlags, counter: 1,
    aaguid, credentialId, coseKey: coseKeyBytes,
  });

  const uvDiscouragedAuthData = buildAuthenticatorData({
    rpId, flags: uvDiscouragedFlags, counter: 1,
    aaguid, credentialId, coseKey: coseKeyBytes,
  });

  // Packed attestation with x5c
  const attestCert = buildSelfSignedCert(
    attestationPublicKey, attestationPrivateKey, 'Yubico U2F EE'
  );

  const packedAuthData = buildAuthenticatorData({
    rpId, flags: uvRequiredFlags, counter: 0,
    aaguid, credentialId, coseKey: coseKeyBytes,
  });

  // Sign authData || clientDataHash with attestation key for packed attestation
  const packedSignedData = Buffer.concat([packedAuthData, regClientDataHash]);
  const packedSig = sign('sha256', packedSignedData, {
    key: attestationPrivateKey,
    dsaEncoding: 'ieee-p1363',
  });

  const packedAttestationObject = buildAttestationObject({
    fmt: 'packed',
    attStmt: {
      alg: -7,
      sig: packedSig,
      x5c: [attestCert],
    },
    authData: packedAuthData,
  });

  const packedAttObjDecoded = cborDecode(packedAttestationObject);

  await explore('Pick a scenario to explore:', [
    {
      name: 'UV required — biometric/PIN verified',
      fn: async () => {
        const { bits, labels } = flagsBreakdown(uvRequiredFlags);
        console.log(`  userVerification: "required" — RP demands identity proof.`);
        console.log();
        console.log(`  Flags byte: 0x${uvRequiredFlags.toString(16)} (binary: ${bits})`);
        console.log();
        labels.forEach(l => console.log(`  ${l}`));
        console.log();
        console.log(`  The UV bit (bit 2) is SET. The authenticator confirmed WHO the`);
        console.log(`  user is — biometric match or PIN entry. The RP knows this is`);
        console.log(`  not just "someone touched the key" but "the registered owner`);
        console.log(`  proved their identity."`);
        console.log();
        console.log(`  Use UV required for: sensitive operations (payments, account`);
        console.log(`  changes, admin actions). The RP policy says "prove you are YOU."`);
      },
    },
    {
      name: 'UV discouraged — presence only',
      fn: async () => {
        const { bits, labels } = flagsBreakdown(uvDiscouragedFlags);
        console.log(`  userVerification: "discouraged" — RP only needs presence.`);
        console.log();
        console.log(`  Flags byte: 0x${uvDiscouragedFlags.toString(16)} (binary: ${bits})`);
        console.log();
        labels.forEach(l => console.log(`  ${l}`));
        console.log();
        console.log(`  The UV bit (bit 2) is CLEAR. The authenticator only confirmed`);
        console.log(`  that someone physically touched it (UP=1), NOT who they are.`);
        console.log(`  No biometric or PIN was required.`);
        console.log();
        console.log(`  Use UV discouraged for: low-risk re-authentication, "tap to`);
        console.log(`  continue" flows. Faster UX — no fingerprint scan or PIN entry.`);
        console.log(`  Trade-off: less assurance about WHO is at the device.`);
      },
    },
    {
      name: 'Attestation "packed" with x5c certificate',
      fn: async () => {
        console.log(`  attestation: "direct" with fmt="packed" — full authenticator proof.`);
        console.log();
        console.log(`  attestationObject decoded:`);
        console.log(`  {`);
        console.log(`    "fmt": "packed",`);
        console.log(`        ↳ Packed attestation format. The authenticator provides`);
        console.log(`          a certificate chain proving its identity.`);
        console.log();
        console.log(`    "attStmt": {`);
        console.log(`      "alg": -7,`);
        console.log(`          ↳ COSE algorithm. -7 = ES256.`);
        console.log();
        console.log(`      "sig": <${packedSig.length} bytes>,`);
        console.log(`          ↳ Signature over authData || clientDataHash, signed`);
        console.log(`            by the attestation private key (NOT the credential key).`);
        console.log();
        console.log(`      "x5c": [<${attestCert.length} bytes>]`);
        console.log(`          ↳ X.509 certificate chain in DER format. First cert is`);
        console.log(`            the authenticator's attestation certificate. Subsequent`);
        console.log(`            certs chain to a root CA. The RP verifies against`);
        console.log(`            FIDO MDS (Metadata Service) root certificates.`);
        console.log(`    },`);
        console.log();
        console.log(`    "authData": <${packedAuthData.length} bytes>`);
        console.log(`  }`);
        console.log();
        console.log(`  AAGUID from authData: ${aaguid.toString('hex')}`);
        console.log(`    ↳ Look this up in FIDO MDS to learn: authenticator name,`);
        console.log(`      capabilities, certification level, known vulnerabilities.`);
        console.log();
        console.log(`  Enterprise use case: "Only allow YubiKey 5 series or higher.`);
        console.log(`  Verify the attestation cert chains to Yubico's root CA,`);
        console.log(`  and the AAGUID matches a known YubiKey 5 model."`);
      },
    },
    {
      name: 'Attestation "none" — privacy-preserving',
      fn: async () => {
        console.log(`  attestation: "none" — authenticator doesn't prove what it is.`);
        console.log();
        console.log(`  attestationObject decoded:`);
        console.log(`  {`);
        console.log(`    "fmt": "none",`);
        console.log(`        ↳ No attestation. The authenticator provides no proof`);
        console.log(`          of its identity or manufacturer.`);
        console.log();
        console.log(`    "attStmt": {},`);
        console.log(`        ↳ Empty object. No signature, no certificate chain.`);
        console.log();
        console.log(`    "authData": <${regAuthData.length} bytes>`);
        console.log(`  }`);
        console.log();
        console.log(`  AAGUID is STILL PRESENT in authData: ${aaguid.toString('hex')}`);
        console.log(`    ↳ The AAGUID is part of attested credential data in`);
        console.log(`      authenticatorData — it's always there when AT=1. But`);
        console.log(`      with fmt="none", the RP has no way to VERIFY it came`);
        console.log(`      from that authenticator model. It's unverified metadata.`);
        console.log();
        console.log(`  Consumer use case: "We don't care what authenticator you use.`);
        console.log(`  Any FIDO2 authenticator is fine. We just need the public key."`);
        console.log(`  Privacy-preserving — the RP can't fingerprint or restrict`);
        console.log(`  authenticator models.`);
      },
    },
    {
      name: 'Cloned authenticator — counter rollback',
      fn: async () => {
        const storedCounter = 5;
        const cloneCounter = 3;

        console.log(`  Scenario: authenticator was cloned (hardware or firmware dump).`);
        console.log(`  The clone starts with a stale counter value.`);
        console.log();
        console.log(`  Stored counter (from last auth):  ${storedCounter}`);
        console.log(`  Counter in this auth response:    ${cloneCounter}`);
        console.log();
        console.log(`  RP check: ${cloneCounter} > ${storedCounter}?`);
        console.log(`  Result: ${cloneCounter} <= ${storedCounter} — ✗ COUNTER ROLLBACK DETECTED`);
        console.log();
        console.log(`  The RP should flag or reject this credential. The counter going`);
        console.log(`  backwards means either:`);
        console.log(`    1. The authenticator was cloned (attacker has a copy)`);
        console.log(`    2. The authenticator's counter was reset (unlikely in practice)`);
        console.log();
        console.log(`  This is the ONLY clone detection mechanism in WebAuthn.`);
        console.log();
        console.log(`  Important caveat: synced passkeys (cloud-backed credentials,`);
        console.log(`  see Experiment 5) often return counter=0 on every authentication.`);
        console.log(`  In that case, counter checking is useless — the RP must rely on`);
        console.log(`  other signals for security. When counter is always 0, skip the`);
        console.log(`  clone check.`);
      },
    },
    {
      name: 'Continue (comparison summary)',
      fn: async () => {
        const { bits: uvReqBits } = flagsBreakdown(uvRequiredFlags);
        const { bits: uvDisBits } = flagsBreakdown(uvDiscouragedFlags);

        console.log(`  ── Comparison: UV required vs UV discouraged ──`);
        console.log();
        console.log(`                    UV required          UV discouraged`);
        console.log(`    ──────────────  ───────────────────  ───────────────────`);
        console.log(`    Flags byte      0x${uvRequiredFlags.toString(16)}                 0x${uvDiscouragedFlags.toString(16)}`);
        console.log(`    Binary          ${uvReqBits}           ${uvDisBits}`);
        console.log(`    UP (presence)   1 ✓                  1 ✓`);
        console.log(`    UV (verified)   1 ✓ (biometric/PIN)  0 (not checked)`);
        console.log(`    AT (cred data)  1 ✓                  1 ✓`);
        console.log(`    Use case        Payments, admin      Low-risk re-auth`);
        console.log();

        await pause();

        console.log(`  ── Comparison: Attestation none vs packed ──`);
        console.log();
        console.log(`                    "none"               "packed" + x5c`);
        console.log(`    ──────────────  ───────────────────  ───────────────────`);
        console.log(`    fmt             "none"               "packed"`);
        console.log(`    attStmt         {} (empty)           { alg, sig, x5c }`);
        console.log(`    AAGUID          Present, unverified  Present, verified`);
        console.log(`    RP knows model  No                   Yes (via FIDO MDS)`);
        console.log(`    Privacy         High (no tracking)   Lower (model known)`);
        console.log(`    Use case        Consumer sites       Enterprise lockdown`);
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
║  Key structures: authenticatorData, clientDataJSON,              ║
║    attestationObject, COSE key, PublicKeyCredentialCreationOpts   ║
║                                                                  ║
║  Q: How does WebAuthn prevent phishing?                          ║
║  A: Browser sets origin in clientDataJSON to actual page URL.    ║
║     Credentials bound to rpId. Neither is overridable.           ║
║                                                                  ║
║  Q: What is the authenticatorData flags byte?                    ║
║  A: Byte at offset 32: UP=presence, UV=biometric/PIN verified,   ║
║     AT=credential data included, ED=extensions present.          ║
║                                                                  ║
║  Q: What does the counter detect?                                ║
║  A: Cloned authenticators. Must increase. If it goes backwards,  ║
║     the credential may be cloned. Synced passkeys return 0.      ║
║                                                                  ║
║  Q: UV required vs discouraged?                                  ║
║  A: Required = biometric/PIN proof (flags 0x45, UV=1). Use for   ║
║     sensitive ops. Discouraged = presence only (0x41, UV=0).     ║
║                                                                  ║
║  Q: How does authentication verification work?                   ║
║  A: Hash clientDataJSON, concatenate authData || hash, verify    ║
║     ECDSA signature with stored public key, check counter >      ║
║     stored value.                                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Draw the authenticatorData byte layout on paper —`);
  console.log(`     label rpIdHash, flags, counter, AAGUID, credentialId, and COSE`);
  console.log(`     key with their byte offsets. Then explain out loud how WebAuthn`);
  console.log(`     prevents phishing (mention origin and rpId). Come back and check`);
  console.log(`     your answer against the summary card above.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

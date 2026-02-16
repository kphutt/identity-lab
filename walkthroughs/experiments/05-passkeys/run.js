#!/usr/bin/env node

// Experiment 5: Passkeys — Sync vs Device-Bound + Attestation
// Layer: Presence
// Run: node run.js (interactive) or node run.js --no-pause (full dump)

import { createHash, randomBytes, generateKeyPairSync, sign, verify } from 'node:crypto';
import { encode as cborEncode } from 'cbor-x';
import { createCLI } from '../../shared/cli.js';

const NO_PAUSE = process.argv.includes('--no-pause');
const { pause, explore, close } = createCLI({ noPause: NO_PAUSE });

// ── Utility Functions (self-contained, copied from Exp 3) ───────

function flagsBreakdown(byte) {
  const bits = byte.toString(2).padStart(8, '0');
  const labels = [
    `  Bit 0 (UP — User Present):              ${(byte & 0x01) ? '1 ✓' : '0'}`,
    `  Bit 1 (RFU):                             ${(byte & 0x02) ? '1' : '0'}`,
    `  Bit 2 (UV — User Verified):              ${(byte & 0x04) ? '1 ✓' : '0'}`,
    `  Bit 3 (BE — Backup Eligible):            ${(byte & 0x08) ? '1 ✓' : '0'}`,
    `  Bit 4 (BS — Backup State):               ${(byte & 0x10) ? '1 ✓' : '0'}`,
    `  Bit 5 (RFU):                             ${(byte & 0x20) ? '1' : '0'}`,
    `  Bit 6 (AT — Attested Credential Data):   ${(byte & 0x40) ? '1 ✓' : '0'}`,
    `  Bit 7 (ED — Extension Data):             ${(byte & 0x80) ? '1' : '0'}`,
  ];
  return { bits, labels };
}

function buildCoseKey(publicKeyJwk) {
  const xBytes = Buffer.from(publicKeyJwk.x, 'base64url');
  const yBytes = Buffer.from(publicKeyJwk.y, 'base64url');
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
    if (value < 0x80) {
      buf = Buffer.from([value]);
    } else {
      const hex = value.toString(16);
      buf = Buffer.from(hex.padStart(hex.length + (hex.length % 2), '0'), 'hex');
      if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
  } else {
    buf = value;
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return Buffer.concat([Buffer.from([0x02]), derLength(buf.length), buf]);
}

function derOid(oidBytes) {
  return Buffer.concat([Buffer.from([0x06]), derLength(oidBytes.length), oidBytes]);
}

function derBitString(data) {
  const body = Buffer.concat([Buffer.from([0x00]), data]);
  return Buffer.concat([Buffer.from([0x03]), derLength(body.length), body]);
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
  const ecPublicKeyOid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const p256Oid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  const sha256WithEcdsaOid = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
  const commonNameOid = Buffer.from([0x55, 0x04, 0x03]);

  const pubJwk = publicKey.export({ format: 'jwk' });
  const xBuf = Buffer.from(pubJwk.x, 'base64url');
  const yBuf = Buffer.from(pubJwk.y, 'base64url');
  const pubPoint = Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);

  const version = derExplicit(0, derInteger(2));
  const serialNumber = derInteger(randomBytes(8));
  const signatureAlgorithm = derSequence(derOid(sha256WithEcdsaOid));
  const issuerName = derSequence(derSet(derSequence(derOid(commonNameOid), derUtf8String(subject))));
  const subjectName = issuerName;

  const now = new Date();
  const later = new Date(now.getTime() + 365 * 24 * 3600 * 1000);
  const formatTime = (d) => {
    const s = d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
    const buf = Buffer.from(s, 'ascii');
    return Buffer.concat([Buffer.from([0x17]), derLength(buf.length), buf]);
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

  const sig = sign('sha256', tbsCertificate, { key: privateKey, dsaEncoding: 'der' });

  return derSequence(
    tbsCertificate,
    derSequence(derOid(sha256WithEcdsaOid)),
    derBitString(sig)
  );
}

// ── Main ────────────────────────────────────────────────────────

async function main() {
  // ── Key Generation ──────────────────────────────────────────

  // 1. Credential keypair — synced passkey's per-credential key
  const credentialKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credentialPublicJwk = credentialKeyPair.publicKey.export({ format: 'jwk' });
  const credentialPrivateKey = credentialKeyPair.privateKey;

  // 2. HW credential keypair — hardware security key's per-credential key
  const hwCredentialKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const hwCredentialPublicJwk = hwCredentialKeyPair.publicKey.export({ format: 'jwk' });
  const hwCredentialPrivateKey = hwCredentialKeyPair.privateKey;

  // 3. Attestation keypair — mock manufacturer key for "packed" attestation
  const attestationKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const attestationPrivateKey = attestationKeyPair.privateKey;
  const attestationPublicKey = attestationKeyPair.publicKey;

  // ── Pre-built Artifacts ─────────────────────────────────────

  const rpId = 'example.com';
  const rpIdHash = createHash('sha256').update(rpId).digest();

  const userId = randomBytes(16);
  const userName = 'alice@example.com';
  const userDisplayName = 'Alice';

  const challenge = randomBytes(32);
  const challengeB64 = challenge.toString('base64url');
  const authChallenge = randomBytes(32);
  const authChallengeB64 = authChallenge.toString('base64url');

  const credentialId = randomBytes(32);
  const credentialIdB64 = credentialId.toString('base64url');
  const hwCredentialId = randomBytes(32);
  const hwCredentialIdB64 = hwCredentialId.toString('base64url');

  // AAGUIDs
  const syncedAaguid = Buffer.from('fbfc3007154e4ecc8c0b6e020557d7bd', 'hex');   // iCloud Keychain (mock)
  const yubiKeyAaguid = Buffer.from('f8a011f38c0a4d15800617111f9edc7d', 'hex');   // YubiKey 5 NFC (mock)
  const platformAaguid = Buffer.from('08987058cadc4b81b6e130de50dcbe96', 'hex');   // Windows Hello / TouchID (mock)

  // COSE keys
  const syncedCoseKey = buildCoseKey(credentialPublicJwk);
  const hwCoseKey = buildCoseKey(hwCredentialPublicJwk);

  // ── Synced passkey registration: flags=0x5D (UP+UV+BE+BS+AT), fmt="none" ──
  const syncedRegFlags = 0x5d;
  const syncedRegAuthData = buildAuthenticatorData({
    rpId, flags: syncedRegFlags, counter: 0,
    aaguid: syncedAaguid, credentialId, coseKey: syncedCoseKey,
  });
  const syncedRegAttObj = buildAttestationObject({
    fmt: 'none', attStmt: {}, authData: syncedRegAuthData,
  });

  // ── HW security key registration: flags=0x45 (UP+UV+AT), fmt="packed" ──
  const hwRegFlags = 0x45;
  const hwRegAuthData = buildAuthenticatorData({
    rpId, flags: hwRegFlags, counter: 0,
    aaguid: yubiKeyAaguid, credentialId: hwCredentialId, coseKey: hwCoseKey,
  });
  const regClientData = {
    type: 'webauthn.create', challenge: challengeB64,
    origin: 'https://example.com', crossOrigin: false,
  };
  const regClientDataJSON = Buffer.from(JSON.stringify(regClientData));
  const regClientDataHash = createHash('sha256').update(regClientDataJSON).digest();

  const attestCert = buildSelfSignedCert(attestationPublicKey, attestationPrivateKey, 'Yubico U2F EE');
  const hwPackedSignedData = Buffer.concat([hwRegAuthData, regClientDataHash]);
  const hwPackedSig = sign('sha256', hwPackedSignedData, {
    key: attestationPrivateKey, dsaEncoding: 'ieee-p1363',
  });
  const hwRegAttObj = buildAttestationObject({
    fmt: 'packed',
    attStmt: { alg: -7, sig: hwPackedSig, x5c: [attestCert] },
    authData: hwRegAuthData,
  });

  // ── Platform authenticator registration: flags=0x45 (UP+UV+AT), fmt="none" ──
  const platformRegFlags = 0x45;
  const platformCredentialId = randomBytes(32);
  const platformCoseKey = buildCoseKey(credentialPublicJwk); // reuse key for display
  const platformRegAuthData = buildAuthenticatorData({
    rpId, flags: platformRegFlags, counter: 0,
    aaguid: platformAaguid, credentialId: platformCredentialId, coseKey: platformCoseKey,
  });

  // ── Passkey authentication: flags=0x1D (UP+UV+BE+BS, no AT), empty allowCredentials ──
  const passkeyAuthFlags = 0x1d;
  const passkeyAuthAuthData = buildAuthenticatorData({
    rpId, flags: passkeyAuthFlags, counter: 0,
  });
  const authClientData = {
    type: 'webauthn.get', challenge: authChallengeB64,
    origin: 'https://example.com', crossOrigin: false,
  };
  const authClientDataJSON = Buffer.from(JSON.stringify(authClientData));
  const authClientDataHash = createHash('sha256').update(authClientDataJSON).digest();
  const passkeyAuthSignedData = Buffer.concat([passkeyAuthAuthData, authClientDataHash]);
  const passkeyAuthSignature = sign('sha256', passkeyAuthSignedData, {
    key: credentialPrivateKey, dsaEncoding: 'ieee-p1363',
  });

  // ── Title Card ──────────────────────────────────────────────

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  Experiment 5: Passkeys — Sync vs Device-Bound + Attestation     ║
║  Layer: Presence                                                 ║
║  Time: ~25 minutes                                               ║
║                                                                  ║
║  Step through with ENTER. Use --no-pause for full dump.          ║
╚══════════════════════════════════════════════════════════════════╝

  Through-line: A passkey is a discoverable credential. Where the
  key lives determines what the RP can trust.

  Builds on Experiment 3 (WebAuthn Ceremonies). Experiment 3 covered
  the WebAuthn ceremonies themselves — authenticatorData binary layout,
  clientDataJSON, attestation formats, flags byte, signature verification.
  This experiment focuses on the credential storage and trust model —
  where the key lives, what the RP can determine, and how to set
  enterprise policy.
`);
  await pause();

  // ── STEP 1: Discoverable vs Non-Discoverable Credentials ──

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 1: Discoverable vs Non-Discoverable Credentials

  A "passkey" is a discoverable credential — the authenticator stores it
  and can find it without the RP providing a credential ID. This is the
  key difference that enables passwordless sign-in.

  ── Registration: Side by Side ──

  PASSKEY (discoverable):                 TRADITIONAL (non-discoverable):
  {                                       {
    "authenticatorSelection": {             "authenticatorSelection": {
      "residentKey": "required",              "residentKey": "discouraged",
          ↳ Stored ON the authenticator.          ↳ NOT stored on authenticator.
            The authenticator keeps the             The RP must store and provide
            credential ID + user info.              the credential ID at login.
      "userVerification": "preferred"         "userVerification": "preferred"
    }                                       }
  }                                       }

  ── Authentication: Side by Side ──

  PASSKEY (empty allowCredentials):       TRADITIONAL (populated allowCredentials):
  {                                       {
    "challenge": "${authChallengeB64.slice(0, 22)}...",    "challenge": "${authChallengeB64.slice(0, 22)}...",
    "allowCredentials": [],                 "allowCredentials": [
        ↳ EMPTY. The authenticator               { "type": "public-key",
          searches its own storage for              "id": "${credentialIdB64.slice(0, 22)}..." }
          credentials matching this rpId.         ↳ RP provides the credential ID.
          No username needed.                       Requires user to identify first
                                                    (type username or select account).
    "mediation": "conditional"              ],
        ↳ Show passkeys in autofill         "userVerification": "preferred"
          dropdown (conditional UI).      }
  }

  The discoverable credential is what makes "Sign in with your passkey"
  possible. The authenticator knows WHO you are at this site — the RP
  doesn't need to ask first.

  🎯 INTERVIEW ALERT: "What is a passkey and how does it differ from a
     regular WebAuthn credential?"
     A passkey is a discoverable credential (residentKey: "required")
     stored ON the authenticator. The authenticator can find it without
     the RP providing a credential ID list. This enables "sign in with
     your passkey" without typing a username. Non-discoverable credentials
     require the RP to provide allowCredentials.
`);
  await pause();

  // ── STEP 2: Backup Flags — BE and BS ──────────────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const { bits: syncedBits, labels: syncedLabels } = flagsBreakdown(syncedRegFlags);
  const { bits: hwBits, labels: hwLabels } = flagsBreakdown(hwRegFlags);

  console.log(`
  STEP 2: Backup Flags — BE and BS

  The flags byte (from Experiment 3, offset 32 in authenticatorData)
  has two bits we glossed over: bits 3 and 4. These are the backup flags
  — they tell the RP WHERE the credential's private key lives.

  ── Synced Passkey (iCloud Keychain) ──

  Flags byte: 0x${syncedRegFlags.toString(16)} (binary: ${syncedBits})
${syncedLabels.map(l => '  ' + l).join('\n')}

  BE=1: This credential CAN be backed up (eligible for cloud sync).
  BS=1: This credential HAS been backed up (it's in the cloud now).
  The private key lives in iCloud Keychain, synced across Apple devices.

  ── Device-Bound Key (YubiKey) ──

  Flags byte: 0x${hwRegFlags.toString(16)} (binary: ${hwBits})
${hwLabels.map(l => '  ' + l).join('\n')}

  BE=0: This credential CANNOT be backed up (not eligible for sync).
  BS=0: This credential has NOT been backed up (it never will be).
  The private key lives in the YubiKey's secure element — it can't
  be exported, cloned, or synced.

  ── Counter Implications ──

  Synced passkeys often return counter=0 on EVERY authentication.
  The credential is accessed from different devices — maintaining a
  monotonic counter across cloud-synced copies is impractical.
  Result: counter-based clone detection (from Experiment 3) is useless
  for synced passkeys. When BE=1, the RP should skip counter checks.

  Device-bound credentials increment the counter normally.
  Counter=0 → 1 → 2 → ... Clone detection works as designed.

  🎯 INTERVIEW ALERT: "What do the backup flags (BE/BS) tell the RP?"
     BE (Backup Eligible) = credential CAN sync to cloud. BS (Backup
     State) = credential HAS synced. RP can make policy decisions:
     require BE=0 for admin accounts (must be device-bound). If BE=1
     and BS=1, counter-based clone detection is useless (counter often
     stays 0).
`);
  await pause();

  // ── STEP 3: Synced Passkey Registration (iCloud Keychain) ─

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 3: Synced Passkey Registration (iCloud Keychain)

  The user registers a passkey on their iPhone. iCloud Keychain stores
  the private key and syncs it to their Mac, iPad, and other devices.

  Registration response:
  {
    "fmt": "none",
        ↳ No attestation. iCloud Keychain doesn't prove it's iCloud
          Keychain — it's a privacy-preserving consumer flow.

    "attStmt": {},
        ↳ Empty. No signature, no certificate chain.

    "authData": <${syncedRegAuthData.length} bytes>
        ↳ flags: 0x${syncedRegFlags.toString(16)} (UP + UV + BE + BS + AT)
  }

  From authenticatorData:
    AAGUID: ${syncedAaguid.toString('hex')}
        ↳ Present — this identifies "iCloud Keychain" as the
          authenticator. But with fmt="none", the RP CANNOT verify
          this AAGUID is genuine. Any software could claim this AAGUID.
          It's unverified metadata (see Experiment 3, attestation "none").

    Credential ID: ${credentialIdB64}
        ↳ The RP stores this, but for passkey auth with conditional UI,
          the RP doesn't need to send it back — the authenticator
          discovers the credential on its own.

    Counter: 0
        ↳ Will stay 0 on future authentications (synced passkey).

  What the RP gains:
    ✓ Discoverable credential — passwordless sign-in
    ✓ Cloud recovery — user gets a new phone, passkey is already there
    ✓ Multi-device — works on iPhone, Mac, iPad seamlessly
    ✗ No hardware assurance — private key is in software (cloud)
    ✗ Trust chain includes Apple's cloud security infrastructure
    ✗ RP cannot verify the authenticator model
`);
  await pause();

  // ── STEP 4: Device-Bound Registration (YubiKey) ───────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 4: Device-Bound Registration (YubiKey 5 NFC)

  The user registers with a YubiKey hardware security key. The private
  key is generated inside the YubiKey's secure element and can never
  be exported.

  Registration response:
  {
    "fmt": "packed",
        ↳ Packed attestation — the YubiKey proves it's a real YubiKey.

    "attStmt": {
      "alg": -7,
          ↳ ES256 — same algorithm, but signed by the ATTESTATION key
            (manufacturer's key baked into the YubiKey), not the
            credential key.

      "sig": <${hwPackedSig.length} bytes>,
          ↳ Signature over authData || SHA-256(clientDataJSON), signed
            by the YubiKey's attestation private key.

      "x5c": [<${attestCert.length} bytes>]
          ↳ Certificate chain: YubiKey's attestation cert → Yubico's
            root CA. The RP verifies this chain against FIDO MDS
            (Metadata Service) root certificates.
    },

    "authData": <${hwRegAuthData.length} bytes>
        ↳ flags: 0x${hwRegFlags.toString(16)} (UP + UV + AT — no BE, no BS)
  }

  From authenticatorData:
    AAGUID: ${yubiKeyAaguid.toString('hex')}
        ↳ With fmt="packed" and a verified x5c chain, this AAGUID is
          TRUSTWORTHY. The RP can look it up:
          → "YubiKey 5 NFC, FIDO2 L1 certified"
          → Secure element, hardware key storage
          → No known vulnerabilities

    Credential ID: ${hwCredentialIdB64}
    Counter: 0 → will increment: 1, 2, 3, ... (clone detection works)

  What the RP gains:
    ✓ Hardware assurance — private key provably in secure element
    ✓ Verified authenticator model via AAGUID + FIDO MDS
    ✓ Counter-based clone detection works
    ✓ Enterprise audit trail — know exactly what hardware is in use
    ✗ No recovery if YubiKey is lost (register backup keys!)
    ✗ Worse UX — user must carry a physical device

  🎯 INTERVIEW ALERT: "What's the difference between a synced passkey
     and a device-bound credential?"
     Synced: private key backed up in cloud (iCloud, Google). Easy
     recovery, great UX. But trust chain includes cloud provider.
     Device-bound: key stays on hardware. Strong assurance (packed
     attestation proves it). But lose the device, lose the credential.
`);
  await pause();

  // ── STEP 5: Passkey Authentication — Conditional UI ───────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const { bits: passkeyAuthBits, labels: passkeyAuthLabels } = flagsBreakdown(passkeyAuthFlags);

  const passkeyVerifyResult = verify(
    'sha256',
    passkeyAuthSignedData,
    { key: credentialKeyPair.publicKey, dsaEncoding: 'ieee-p1363' },
    passkeyAuthSignature
  );

  console.log(`
  STEP 5: Passkey Authentication — Conditional UI

  The user returns to sign in. The RP calls navigator.credentials.get()
  with EMPTY allowCredentials and mediation: "conditional".

  RP sends:
  {
    "challenge": "${authChallengeB64}",

    "allowCredentials": [],
        ↳ EMPTY. Contrast with Experiment 3's auth, where the RP sent
          the stored credential ID. Here, the authenticator discovers
          the credential by rpId alone — because it's a discoverable
          credential (passkey).

    "mediation": "conditional",
        ↳ Instead of a WebAuthn modal popup, passkeys appear in the
          browser's autofill dropdown alongside saved passwords. The
          user taps a passkey entry to authenticate — no modal, no
          disruption. The <input autocomplete="username webauthn">
          attribute triggers this in the HTML.

    "userVerification": "preferred"
  }

  Authenticator responds:

  authenticatorData (${passkeyAuthAuthData.length} bytes — no AT, auth only):
    flags: 0x${passkeyAuthFlags.toString(16)} (binary: ${passkeyAuthBits})
${passkeyAuthLabels.map(l => '    ' + l).join('\n')}

    UP=1, UV=1, BE=1, BS=1, AT=0
        ↳ BE and BS are STILL SET during authentication — they reflect
          the credential's backup status, not just a registration flag.
          AT=0 because credential data is only in registration.

    counter: 0
        ↳ Synced passkey — counter stays 0. Skip clone check.

  ── Signature Verification ──

  authData || SHA-256(clientDataJSON) → ${passkeyAuthSignedData.length} bytes
  Signature: ${passkeyAuthSignature.toString('hex').slice(0, 40)}...
  Verify with stored public key: ${passkeyVerifyResult ? '✓ Signature valid' : '✗ Signature invalid'}

  The RP also receives userHandle (the user.id from registration),
  which identifies the account — no username entry needed.

  🎯 INTERVIEW ALERT: "How does conditional UI work for passkeys?"
     Browser calls navigator.credentials.get() with mediation:
     "conditional". Instead of a WebAuthn modal, passkeys appear in
     the username field's autofill dropdown alongside saved passwords.
     User taps a passkey to authenticate. Requires discoverable
     credentials.
`);
  await pause();

  // ── STEP 6: Credential Registration Policy Lab ────────────

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`
  STEP 6: Credential Registration Policy Lab

  Different authenticator types produce different registration responses.
  Explore each scenario to understand what the RP can learn and trust.`);

  await explore('Pick a scenario to explore:', [
    {
      name: 'Synced passkey (iCloud Keychain)',
      fn: async () => {
        const { bits, labels } = flagsBreakdown(syncedRegFlags);
        console.log(`  Authenticator: iCloud Keychain (Apple platform, synced via iCloud)`);
        console.log();
        console.log(`  Registration response:`);
        console.log(`    fmt:      "none" (no attestation)`);
        console.log(`    attStmt:  {} (empty)`);
        console.log(`    flags:    0x${syncedRegFlags.toString(16)} (binary: ${bits})`);
        console.log();
        labels.forEach(l => console.log(`  ${l}`));
        console.log();
        console.log(`    AAGUID:   ${syncedAaguid.toString('hex')}`);
        console.log(`              ↳ Identifies "iCloud Keychain" — but UNVERIFIED.`);
        console.log(`                With fmt="none", any software could claim this AAGUID.`);
        console.log();
        console.log(`    Counter:  0 (will stay 0 — synced across devices)`);
        console.log();
        console.log(`  Trust model:`);
        console.log(`    • Private key lives in iCloud Keychain (cloud-backed, encrypted)`);
        console.log(`    • Synced to all Apple devices signed into the same Apple ID`);
        console.log(`    • Easy recovery: new device → passkeys sync automatically`);
        console.log(`    • Trust chain now includes Apple's cloud security`);
        console.log(`    • BE=1, BS=1 → RP knows this is cloud-backed`);
        console.log(`    • No hardware assurance — RP cannot prove key is in secure element`);
      },
    },
    {
      name: 'Hardware security key (YubiKey 5 NFC)',
      fn: async () => {
        const { bits, labels } = flagsBreakdown(hwRegFlags);
        console.log(`  Authenticator: YubiKey 5 NFC (USB/NFC hardware security key)`);
        console.log();
        console.log(`  Registration response:`);
        console.log(`    fmt:      "packed" (full attestation with certificate chain)`);
        console.log(`    attStmt:  { alg: -7, sig: <${hwPackedSig.length} bytes>, x5c: [<${attestCert.length} bytes>] }`);
        console.log(`    flags:    0x${hwRegFlags.toString(16)} (binary: ${bits})`);
        console.log();
        labels.forEach(l => console.log(`  ${l}`));
        console.log();
        console.log(`    AAGUID:   ${yubiKeyAaguid.toString('hex')}`);
        console.log(`              ↳ VERIFIED via x5c certificate chain.`);
        console.log(`                FIDO MDS lookup → "YubiKey 5 NFC, FIDO2 L1 certified"`);
        console.log(`                Secure element, hardware key storage, no known vulns.`);
        console.log();
        console.log(`    Counter:  0 → will increment: 1, 2, 3, ...`);
        console.log();
        console.log(`  Trust model:`);
        console.log(`    • Private key generated and stored in YubiKey's secure element`);
        console.log(`    • Key CANNOT be exported, cloned, or backed up`);
        console.log(`    • BE=0, BS=0 → RP knows this is device-bound`);
        console.log(`    • Packed attestation + x5c → RP verifies exact hardware model`);
        console.log(`    • Counter increments normally → clone detection works`);
        console.log(`    • Loss = credential gone. Register 2+ keys for recovery.`);
      },
    },
    {
      name: 'Platform authenticator (TouchID / Windows Hello)',
      fn: async () => {
        const { bits, labels } = flagsBreakdown(platformRegFlags);
        console.log(`  Authenticator: Platform (TouchID on Mac, Windows Hello on PC)`);
        console.log();
        console.log(`  Registration response:`);
        console.log(`    fmt:      "none" (typically no attestation)`);
        console.log(`    attStmt:  {} (empty)`);
        console.log(`    flags:    0x${platformRegFlags.toString(16)} (binary: ${bits})`);
        console.log();
        labels.forEach(l => console.log(`  ${l}`));
        console.log();
        console.log(`    AAGUID:   ${platformAaguid.toString('hex')}`);
        console.log(`              ↳ Identifies platform authenticator (unverified).`);
        console.log();
        console.log(`    authenticatorAttachment: "platform"`);
        console.log(`              ↳ Built-in to the device. Not portable — can't plug`);
        console.log(`                your Mac's TouchID into a Windows PC.`);
        console.log();
        console.log(`  Trust model:`);
        console.log(`    • Key stored in platform's secure enclave (TPM / Secure Enclave)`);
        console.log(`    • Device-bound but NOT portable across devices`);
        console.log(`    • Lose the device → lose the credential`);
        console.log(`    • Register on EACH device separately (laptop + phone + tablet)`);
        console.log(`    • Biometric verification via TouchID/FaceID/Windows Hello PIN`);
        console.log(`    • Great UX on that specific device, but no roaming capability`);
        console.log();
        console.log(`  Recovery strategy:`);
        console.log(`    • Register multiple platform credentials (one per device)`);
        console.log(`    • Keep a backup hardware key (YubiKey) for account recovery`);
        console.log(`    • OR combine with a synced passkey for seamless recovery`);
      },
    },
    {
      name: 'Phone as authenticator (hybrid transport)',
      fn: async () => {
        console.log(`  Cross-device authentication: phone authenticates for a laptop.`);
        console.log();
        console.log(`  Scenario: User is at a shared PC (hotel, library) with no`);
        console.log(`  registered credentials. Their passkey is on their phone.`);
        console.log();
        console.log(`  ── Hybrid Transport Flow ──`);
        console.log();
        console.log(`  1. Laptop shows a QR code`);
        console.log(`     ↳ Contains a one-time pairing code + Bluetooth LE advert info.`);
        console.log(`       The QR code links to the FIDO CTAP2 hybrid transport.`);
        console.log();
        console.log(`  2. User scans QR code with phone camera`);
        console.log(`     ↳ Phone recognizes FIDO2 intent, opens passkey UI.`);
        console.log();
        console.log(`  3. Bluetooth proximity check`);
        console.log(`     ↳ Phone and laptop establish BLE connection to verify`);
        console.log(`       physical proximity. Prevents remote relay attacks.`);
        console.log();
        console.log(`  4. Phone's authenticator handles the WebAuthn ceremony`);
        console.log(`     ↳ User verifies with biometric (TouchID/FaceID).`);
        console.log(`       Phone signs the challenge with its stored passkey.`);
        console.log();
        console.log(`  5. Response tunneled back to laptop`);
        console.log(`     ↳ Signed assertion travels phone → BLE → laptop → browser → RP.`);
        console.log(`       The RP sees a normal WebAuthn response — it doesn't know`);
        console.log(`       or care that the authenticator was a phone.`);
        console.log();
        console.log(`  From the laptop's perspective:`);
        console.log(`    authenticatorAttachment: "cross-platform"`);
        console.log(`        ↳ The phone acts as a roaming authenticator for the laptop.`);
        console.log(`          The laptop has no registered credentials — the phone has them.`);
        console.log();
        console.log(`  From the phone's perspective:`);
        console.log(`    It's using its platform authenticator (TouchID/FaceID) + synced`);
        console.log(`    passkey from iCloud Keychain or Google Password Manager.`);
      },
    },
    {
      name: 'Continue (comparison + enterprise policy)',
      fn: async () => {
        console.log(`  ── Credential Type Comparison ──`);
        console.log();
        console.log(`                        Synced           Device-bound      Platform`);
        console.log(`                        (iCloud/Google)  (YubiKey)         (TouchID/Hello)`);
        console.log(`  ────────────────────  ───────────────  ────────────────  ────────────────`);
        console.log(`  Attestation format    "none"           "packed" + x5c   "none" (typical)`);
        console.log(`  AAGUID usable?        Present,         Present,          Present,`);
        console.log(`                        unverified       VERIFIED          unverified`);
        console.log(`  Hardware assurance    No               Yes (proven)      Partial (TPM)`);
        console.log(`  Key exportable?       Cloud-synced     No (never)        No (device-bound)`);
        console.log(`  Recovery story        Automatic        Register backup   Per-device, no`);
        console.log(`                        (cloud sync)     keys              roaming`);
        console.log(`  BE flag               1                0                 0`);
        console.log(`  BS flag               1                0                 0`);
        console.log(`  Counter behavior      Always 0         Incrementing      Incrementing`);
        console.log(`  Clone detection       No               Yes               Yes`);
        console.log();
        await pause();

        console.log(`  ── Enterprise Credential Policy Guidance ──`);
        console.log();
        console.log(`  Admin / privileged accounts:`);
        console.log(`    → Require device-bound credentials (BE=0)`);
        console.log(`    → Require "packed" attestation with verified x5c chain`);
        console.log(`    → AAGUID allowlisting: only approved hardware models`);
        console.log(`      (e.g., "Only YubiKey 5 series or FIDO2 L2 certified devices")`);
        console.log(`    → Register 2+ keys per admin (primary + backup)`);
        console.log(`    → Enable counter-based clone detection`);
        console.log();
        console.log(`  General workforce:`);
        console.log(`    → Allow synced passkeys (BE=1 acceptable)`);
        console.log(`    → Accept "none" attestation (don't restrict authenticator model)`);
        console.log(`    → Balance security with UX: synced passkeys = no lockouts`);
        console.log(`    → Encourage enrollment of multiple credentials for recovery`);
        console.log();
        console.log(`  Enforcement mechanisms:`);
        console.log(`    → Check BE/BS flags at registration time: reject BE=1 for`);
        console.log(`      admin accounts that require device-bound credentials`);
        console.log(`    → Verify attestation format: require fmt="packed" for high-trust`);
        console.log(`    → Validate x5c chain against FIDO MDS root certificates`);
        console.log(`    → Match AAGUID against allowed authenticator model list`);
        console.log(`    → Store credential metadata (BE, BS, fmt, AAGUID) for audit`);
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
║  Q: What is a passkey?                                           ║
║  A: A discoverable WebAuthn credential (residentKey: "required").║
║     Stored on authenticator, found without allowCredentials.     ║
║     Enables passwordless sign-in.                                ║
║                                                                  ║
║  Q: Synced vs device-bound?                                      ║
║  A: Synced: cloud backup, easy recovery, less assurance,         ║
║     counter=0. Device-bound: hardware only, packed attestation,  ║
║     strong assurance, no recovery if lost.                       ║
║                                                                  ║
║  Q: What do BE/BS flags mean?                                    ║
║  A: BE = credential CAN sync. BS = credential HAS synced. RP    ║
║     uses these for policy: require BE=0 for privileged accounts. ║
║                                                                  ║
║  Q: How does conditional UI work?                                ║
║  A: mediation: "conditional" shows passkeys in autofill dropdown.║
║     No WebAuthn modal. Requires discoverable credentials.        ║
║                                                                  ║
║  Q: Enterprise passkey policy?                                   ║
║  A: Device-bound + packed attestation for admin accounts (AAGUID ║
║     allowlisting). Synced passkeys for general workforce         ║
║     (balance security with UX).                                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);

  // ── Practice Prompt ─────────────────────────────────────────

  console.log(`  ⏸  PRACTICE: Draw two credential registrations side by side:`);
  console.log(`     synced passkey (iCloud Keychain) and device-bound (YubiKey).`);
  console.log(`     Label the flags byte (especially BE/BS), attestation format,`);
  console.log(`     and AAGUID verification status. Then explain when an enterprise`);
  console.log(`     should require device-bound credentials and how to enforce it.`);
  console.log();

  close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
